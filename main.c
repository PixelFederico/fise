// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define FILES_PATH "/var/lib/fise/api/"
#define CONFIG_PATH "/etc/fise/"
#define PUBKEY_PATH CONFIG_PATH "pubkey"
#define MAX_UPLOAD_SIZE 15LL * 1024 * 1024 * 1024 // 15 GB
#define HEADERS_MAX_SIZE                                                       \
	24LL * 1024 // 5 KB. The maximum size of headers a client can send. This
	            // value have to be less than MAX_BUFFER
#define LISTEN_BACKLOG 4096
#define MAX_BUFFER                                                             \
	4 * 1024 * 1024 // 4 MB. The maximum the server/client can read or
	                // write withone call (not always applied by the server in
	                // write when the response is not too large)
#define MAX_EVENTS 100

#define ALLOW_METHODS "GET, POST, OPTIONS, DELETE"
#define ALLOW_ORIGIN "*"
#define ALLOW_HEADERS "*"

static volatile int running = 1;

void intHandler(int sig) {
	if (sig == SIGINT) running = 0;
}

enum CLIENT_STATUS {
	STATUS_IDLE,
	STATUS_SENDING_HEADERS,
	STATUS_DOWNLOADING,
	STATUS_UPLOADING,
	STATUS_DISCONNECTED,
	STATUS_WAITING_UPLOAD_ID
};

enum REQUIRE_AUTH_LEVEL { REQUEST_USER, REQUEST_ADMIN };

/*
 * This is the structure of the job that each client have
 * If the client is uploading something to the server the uplodaded field will
 * be used with status = STATUS_UPLOADING and the id and uploaded_bytes fields
 * will be used, if the client is downloading from the server the beginning, end
 * and size fields will be used with status = STATUS_DOWNLOADING, in the case of
 * STATUS_DOWNLOADING the download will finish when (end - beginning) <=
 * MAX_BUFFER
 */
struct s_job {
	char *headers; // Raw headers of the request. These headers are not expected
	               // to be full as a client can only send a part of headers (to
	               // send the remaining in a later write), or when the read
	               // length is greater than MAX_BUFFER (so other read calls are
	               // needed)
	unsigned long body_chunk_len;
	char         *body_chunk; // A piece of the client body to be processed
	                          // by server
	unsigned int headers_len;
	int          clientfd;
	int          status;
	int          filefd;
	union {
		struct {
			char *id;                  /* The name of the folder where the
			                            * uploaded file should reside.
			                            * FORMAT: FILES_PATH/id/file_name */
			unsigned long upload_size; /* The number of bytes that the user want to
			                              upload to server */
			unsigned long
			    uploaded_bytes; /* The number of current uploaded bytes by the
			                       user. Used to limit the size of upload when it
			                       exceeds the content length */
		};
		struct {
			ssize_t beginning; /* This field is used to know which part of
			                    * the file the client is asking to
			                    * download, it is the number of bytes to
			                    * skip from the beginning of the file. This field
			                    * will  also change each time the server sends a
			                    * chunk of the  file to save the download status */
			ssize_t end;       /* This field is used to know which part of
			                    * the file the client is asking to
			                    * download, it is the number in bytes where the
			                    * download finishes */
		};
	};
};

typedef struct s_job job;

struct s_fise {
	struct sockaddr_in *addr;
	struct epoll_event *events;
	job                *jobs;
	char               *pubkey; // NULL if disabled
	int                 sockfd;
	int                 epfd;
	int                 n_jobs;
};

typedef struct s_fise fise;

struct s_header_node {
	char *key;
	char *value;
	char *keys; // Pointer to all keys contained in the current instance and
	            // next (recursive). This pointer is only contained at the
	            // instance where it begins the first use of the same
	struct s_header_node *next;
};

typedef struct s_header_node header_node;

/*
 * Wrapper of the malloc function, if there is an error the program stops
 */
void *safe_malloc(size_t size) {
	void *ptr = malloc(size);
	if (ptr == NULL) {
		perror("Malloc failed");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

/*
 * Wrapper of the realloc function, if there is an error the program stops
 */
void *safe_realloc(void *ptr, size_t size) {
	void *new_ptr = realloc(ptr, size);
	if (new_ptr == NULL) {
		perror("Realloc failed");
		exit(EXIT_FAILURE);
	}
	return new_ptr;
}

/*
 * Deletes path directory recursively.
 * returns: 0 for success, -1 for error
 */
int remove_directory(const char *path) {
	DIR   *d        = opendir(path);
	size_t path_len = strlen(path);
	int    r        = -1;

	if (d) {
		struct dirent *p;
		r = 0;

		while (!r && (p = readdir(d))) {
			int    r2 = -1;
			char  *buf;
			size_t len;

			// Skip "." and ".."
			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) continue;

			len = path_len + strlen(p->d_name) + 2;
			buf = safe_malloc(len);

			struct stat statbuf;
			snprintf(buf, len, "%s/%s", path, p->d_name);

			if (!stat(buf, &statbuf)) {
				if (S_ISDIR(statbuf.st_mode))
					r2 = remove_directory(buf);
				else
					r2 = unlink(buf);
			}
			free(buf);
			r = r2;
		}
		closedir(d);
	}

	if (!r) r = rmdir(path);

	return r;
}

/*
 * Decodes the base64 url encoded input string of input_len length, and sets
 * output_len as the decoded length output
 * returns: the ptr to the decoded output. Remember to free after use
 */
unsigned char *base64url_decode(const char *input, const size_t input_len,
                                size_t *output_len) {
	// PLANNED: replace that to directly decode the base64 url instead of
	// converting it to base64 before

	// Replace '-' with '+' and '_' with '/'
	char *base64_str = safe_malloc(input_len + 1);

	for (size_t i = 0; i < input_len; i++) {
		if (input[i] == '-') {
			base64_str[i] = '+';
		} else if (input[i] == '_') {
			base64_str[i] = '/';
		} else {
			base64_str[i] = input[i];
		}
	}
	base64_str[input_len] = '\0';

	size_t padding        = (4 - (input_len % 4)) % 4;
	if (padding > 0) {
		// Add padding
		base64_str = safe_realloc(base64_str, input_len + padding + 1);
		for (size_t i = 0; i < padding; i++) {
			base64_str[input_len + i] = '=';
		}
		base64_str[input_len + padding] = '\0';
	}

	BIO           *bio, *b64;
	size_t         decode_len = strlen(base64_str);
	unsigned char *buffer     = safe_malloc(decode_len);

	bio                       = BIO_new_mem_buf(base64_str, -1);
	b64                       = BIO_new(BIO_f_base64());
	bio                       = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*output_len = BIO_read(bio, buffer, decode_len);

	BIO_free_all(bio);
	free(base64_str);

	return buffer;
}

/*
 * Changes the sockaddr structure to set the given addr and port. The structure
 * is expected to be already allocated in memory
 * returns: 0 for success, -1 for error
 */
int create_address(struct sockaddr_in *sockaddr, const char *addr,
                   const uint16_t port) {
	int result_pton;

	// Allocate the address
	result_pton = inet_pton(AF_INET, addr, &sockaddr->sin_addr.s_addr);
	if (result_pton <= 0) {
		if (result_pton == 0)
			perror("Not in presentation format");
		else
			perror("Failed to call inet_pton");
		return -1;
	}
	sockaddr->sin_family = AF_INET;

	// Allocate the port
	sockaddr->sin_port = htons(port);

	return 0;
}
/*
 * Closes data's file descriptors and frees non-null memory
 */
void close_socket(fise *data) {
	if (data->addr) {
		free(data->addr);
	}
	if (data->events) {
		free(data->events);
	}
	if (data->jobs) {
		free(data->jobs);
	}
	if (data->pubkey) {
		free(data->pubkey);
	}
	if (data->epfd) {
		if (close(data->epfd) == -1) {
			perror("Error while closing epfd");
			exit(EXIT_FAILURE);
		}
	}
	if (data->sockfd) {
		if (close(data->sockfd) == -1) {
			perror("Error while closing socket");
			exit(EXIT_FAILURE);
		}
	}
	free(data);
}
/*
 * Creates a new TCP socket binded to 'addr' address and 'port' port. Sets
 * sockfd as the file descriptor of the created socket and sockaddr as the
 * structure of the address
 * returns: 0 for success, -1 for error
 */
int create_socket(const char *addr, const uint16_t port,
                  struct sockaddr_in *sockaddr, int *sockfd) {
	unsigned long addrlen;

	if (create_address(sockaddr, addr, port) == -1) {
		return -1;
	}

	addrlen = sizeof(*sockaddr);

	*sockfd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (*sockfd == -1) {
		perror("Error in socket creation");
		return -1;
	}

	const int sock_reuse = 1;

	if (setsockopt(*sockfd, SOL_SOCKET, SO_REUSEADDR, &sock_reuse,
	               sizeof(sock_reuse)) == -1) {
		perror("Error while setting socket options");
		return -1;
	}
	if (bind(*sockfd, (struct sockaddr *)sockaddr, addrlen)) {
		perror("Error in socket address binding");
		return -1;
	}

	return 0;
}

/*
 * Initializes the members of data and creates the socket at 'addr' address and
 * 'port' port
 * returns: 0 for success, -1 for error
 */
int create_http_server(fise *data, const char *addr, const uint16_t port) {
	data->addr   = (struct sockaddr_in *)safe_malloc(sizeof(struct sockaddr_in));
	data->sockfd = 0;
	data->n_jobs = 0;
	data->epfd   = 0;
	data->events = NULL;
	data->jobs   = NULL;
	data->pubkey = NULL;
	FILE *pubkey_file = fopen(PUBKEY_PATH, "r");
	if (pubkey_file) {
		char   *line = NULL;
		size_t  len  = 0;
		ssize_t read = getline(&line, &len, pubkey_file);
		if (read > 0) {
			if (line[read - 1] == '\n') {
				line[read - 1] = '\0';
				read--;
			}
			if (read > 0) {
				data->pubkey = line;
			} else {
				free(line);
			}
		} else if (line != NULL) {
			free(line);
		}
		fclose(pubkey_file);
	}
	return create_socket(addr, port, data->addr, &data->sockfd);
}

/* Starts the socket to listen for events. Sets epfd as the file descriptor of
 * the epoll
 * returns: 0 for success, -1 for error
 */
int socket_start_listener(const int sockfd, int *epfd) {
	if (listen(sockfd, LISTEN_BACKLOG) == -1) {
		perror("Error in socket listening");
		return -1;
	}
	*epfd = epoll_create1(0);

	struct epoll_event *socketfd_event =
	    (struct epoll_event *)safe_malloc(sizeof(struct epoll_event));
	socketfd_event->events  = EPOLLIN;
	socketfd_event->data.fd = sockfd;

	if (epoll_ctl(*epfd, EPOLL_CTL_ADD, sockfd, socketfd_event) == -1) {
		free(socketfd_event);
		perror("Error while adding the server socket to events listener");
		return -1;
	}
	free(socketfd_event);
	return 0;
}

/* Sends message of message_len length to clientfd peer
 * returns: The length of the message that server has successfully sent. The
 * length can be less than message_len if the client blocked the socket
 * listening while sending
 */
size_t socket_send(const int clientfd, const char *message,
                   const size_t message_len) {
	// PLANNED: there is a rare edge case where the client can't read the full
	// message and the server should save the remaining data and retry when
	// client is ready, but for now is not handled to prevent denial of service
	// by having a lot of clients not ready. It's only handled by
	// process_download_chunk
	size_t total_sent = 0;
	while (total_sent < message_len) {
		const char *remaining_sbuf = message + total_sent;
		ssize_t     sent =
		    send(clientfd, remaining_sbuf, message_len - total_sent, 0);
		if (sent == (ssize_t)-1) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				perror("Error while sending message");
			}
			break;
		}
		total_sent += sent;
	}
	return total_sent;
}

/*
 * Frees headers linked list recursively, also frees keys
 */
void free_headers(header_node *headers) {
	if (headers->keys) free(headers->keys);
	if (headers->next != NULL) free_headers(headers->next);
	free(headers);
}

/*
 * Puts the given headers in a linked list for easier access. labels is expected
 * to be a list of headers keys each separated by a comma, the rest of the
 * passed values (...) are expected to be in the same order of the labels
 * because they are the values
 * correct usage example: header_node *headers =
 * create_headers("X-HEADER-KEY-1,X-HEADER-KEY-2", header_value_1,
 * header_value_2);
 * returns: the pointer of the memory of the headers or NULL for errors.
 * Remember to free after use with free_headers function
 */
header_node *create_headers(const char *labels, ...) {
	if (!labels) return NULL;

	char *labels_copy = strdup(labels);
	if (!labels_copy) return NULL;

	header_node *head        = NULL;
	header_node *last_header = NULL;
	va_list      args;
	va_start(args, labels);

	char *label = strtok(labels_copy, ",");
	while (label != NULL) {
		header_node *current_header = safe_malloc(sizeof(header_node));

		current_header->key         = label;
		current_header->value       = va_arg(args, char *);
		current_header->next        = NULL;

		if (!head) {
			head       = current_header;
			head->keys = labels_copy;
		} else {
			current_header->keys = NULL;
			last_header->next    = current_header;
		}
		last_header = current_header;

		label       = strtok(NULL, ",");
	}

	va_end(args);
	return head;
}

/*
 * Sends http response to clientfd with the 'code' response code, with the
 * passed headers and message as the body. If 'headers' is null it only sends
 * the necessary headers, if 'message' is null it will not send the body
 * returns: 0 for success, -1 for error
 */
int http_send_response(const int clientfd, const char *code,
                       header_node *headers, const char *message) {
	char *response_body = NULL;
	if (message) {
		if (*code == '2') {
			// Success response
			int body_len = snprintf(NULL, 0, "{\"success\":\"%s\"}", message);
			if (body_len < 0) {
				if (headers) free_headers(headers);
				return -1;
			}
			response_body = safe_malloc(body_len + 1);
			if (sprintf(response_body, "{\"success\":\"%s\"}", message) < 0) {
				free(response_body);
				if (headers) free_headers(headers);
				return -1;
			}
		} else {
			// Error response
			int body_len = snprintf(NULL, 0, "{\"error\":\"%s\"}", message);
			if (body_len < 0) {
				if (headers) free_headers(headers);
				return -1;
			}
			response_body = safe_malloc(body_len + 1);
			if (sprintf(response_body, "{\"error\":\"%s\"}", message) < 0) {
				free(response_body);
				if (headers) free_headers(headers);
				return -1;
			}
		}
	}
	header_node *cors_headers = create_headers(
	    "Access-Control-Allow-Methods,Access-Control-Allow-"
	    "Origin,Access-Control-Allow-Headers,Content-Type",
	    ALLOW_METHODS, ALLOW_ORIGIN, ALLOW_HEADERS, "application/json");
	if (headers) {
		header_node *headers_tail = headers;
		while (headers_tail->next != NULL) {
			headers_tail = headers_tail->next;
		}
		headers_tail->next = cors_headers;
	} else {
		headers = cors_headers;
	}
	int len = snprintf(NULL, 0, "HTTP/1.1 %s\r\n", code);
	if (len < 0) {
		if (message) free(response_body);
		free_headers(headers);
		return -1;
	}
	char *response = safe_malloc(len + 1);
	if (sprintf(response, "HTTP/1.1 %s\r\n", code) < 0) {
		free(response);
		if (message) free(response_body);
		free_headers(headers);
		return -1;
	}
	socket_send(clientfd, response, len);
	free(response);
	{
		// Convert each entry of the headers linked list and send on the socket
		header_node *current_header = headers;
		do {
			int header_len = snprintf(NULL, 0, "%s:%s\r\n", current_header->key,
			                          current_header->value);
			if (header_len < 0) {
				if (message) free(response_body);
				free_headers(headers);
				return -1;
			}

			char *header = safe_malloc(header_len + 1);
			if (sprintf(header, "%s:%s\r\n", current_header->key,
			            current_header->value) < 0) {
				free(header);
				if (message) free(response_body);
				free_headers(headers);
				return -1;
			}
			socket_send(clientfd, header, header_len);
			free(header);
			current_header = current_header->next;
		} while (current_header);
	}
	if (message) {
		int header_len = snprintf(NULL, 0, "Content-Length:%lu\r\n\r\n",
		                          strlen(response_body));
		if (header_len < 0) {
			free(response_body);
			free_headers(headers);
			return -1;
		}

		char *header = safe_malloc(header_len + 1);
		if (sprintf(header, "Content-Length:%lu\r\n\r\n", strlen(response_body)) <
		    0) {
			free(header);
			free(response_body);
			free_headers(headers);
			return -1;
		}
		socket_send(clientfd, header, header_len);
		free(header);
		socket_send(clientfd, response_body, strlen(response_body));
		free(response_body);
	} else {
		socket_send(clientfd, "\r\n", 2);
	}
	free_headers(headers);
	return 0;
}

/*
 * Finds the http header value of the 'header' key in the given request of
 * request_len size
 * returns: the pointer of the found value of the header, null if not found or
 * if the request is malformed. Remember of free after use
 */
char *find_http_header_value(char *request, const size_t request_len,
                             const char *header) {
	size_t header_len = strlen(header);
	char  *end        = request + request_len;

	char *pos         = request;
	char *header_line = NULL;

	while (pos < end) {
		if (strncasecmp(pos, header, header_len) == 0) {
			header_line = pos;
			break;
		}
		char *next_line = memmem(pos, end - pos, "\r\n", 2);
		if (next_line == NULL) break;
		pos = next_line + 2;
	}
	if (header_line == NULL) return NULL;

	char *colon = memchr(header_line, ':', end - header_line);
	if (colon == NULL || colon >= end) {
		return NULL;
	}

	char *value_start = colon + 1;
	// Skip any space
	while (value_start < end && (*value_start == ' ' || *value_start == '\t')) {
		value_start++;
	}

	char *value_end = memmem(value_start, end - value_start, "\r\n", 2);
	if (value_end == NULL) return NULL;

	size_t value_len = value_end - value_start;
	char  *value     = safe_malloc(value_len + 1);
	memcpy(value, value_start, value_len);
	value[value_len] = '\0';

	return value;
}

/*
 * Adds new_job to data->jobs, new_job replaces the first job found with
 * STATUS_DISCONNECTED if present, otherwise adds a new entry by resizing the
 * array
 */
void add_job(fise *data, const job *new_job) {
	// First search for disconnected jobs to replace with
	for (int i = 0; i < data->n_jobs; i++) {
		if (data->jobs[i].status == STATUS_DISCONNECTED) {
			data->jobs[i] = *new_job;
			return;
		}
	}

	// Add new job by extending the array
	data->n_jobs++;
	size_t job_size = sizeof(job);
	job   *new_jobs = safe_realloc(data->jobs, (job_size * data->n_jobs));
	data->jobs      = new_jobs;
	data->jobs[data->n_jobs - 1] = *new_job;
}

/*
 * Find the job from data->jobs of the passed clientfd
 * returns: the found job, otherwise null if not present
 */
job *find_client_job(fise *data, int clientfd) {
	for (int i = 0; i < data->n_jobs; i++) {
		if (data->jobs[i].clientfd == clientfd) {
			return &data->jobs[i];
		}
	}
	return NULL;
}

/*
 * Deletes a client of the given current_job from data_epfd and closes the
 * connection. Sets the status of the job to STATUS_DISCONNECTED, does a full
 * cleanup of the job by also freeing non-null members (and sets them to null)
 * and closes the filefd if open
 */
void disconnect_client(const int data_epfd, job *current_job) {
	if (epoll_ctl(data_epfd, EPOLL_CTL_DEL, current_job->clientfd, NULL) == -1) {
		perror("Error while removing the peer from events listener");
		exit(EXIT_FAILURE);
	}
	if (close(current_job->clientfd) == -1) {
		perror("Error while closing connection");
		exit(EXIT_FAILURE);
	}
	current_job->clientfd = 0;
	if (current_job->filefd >= 0) {
		if (close(current_job->filefd) == -1) {
			perror("Error while closing file");
			exit(EXIT_FAILURE);
		}
		current_job->filefd = 0;
	}
	if (current_job->headers_len > 0) {
		free(current_job->headers);
		current_job->headers     = NULL;
		current_job->headers_len = 0;
	}
	if (current_job->body_chunk_len > 0) {
		free(current_job->body_chunk);
		current_job->body_chunk     = NULL;
		current_job->body_chunk_len = 0;
	}
	if ((current_job->status == STATUS_UPLOADING ||
	     current_job->status == STATUS_WAITING_UPLOAD_ID) &&
	    current_job->id) {
		free(current_job->id);
		current_job->id = NULL;
	}
	current_job->status = STATUS_DISCONNECTED;
}

/* Takes a chunk (of MAX_BUFFER size or less if it would exceed the file length)
 * of the file current_job->filefd and sends it to current_job->clientfd
 * returns: -1 if it was the last chunk of the file or if an error occurred, 0
 * if the file upload is not finished yet
 */
int process_download_chunk(job *current_job) {
	if (current_job->filefd < 0) {
		printf("File to upload to client not found!\n");
		return -1;
	}

	size_t remaining_bytes = current_job->end + 1 - current_job->beginning;
	int    is_last         = 0;
	size_t chunk_size;

	if (remaining_bytes <= MAX_BUFFER) {
		chunk_size = remaining_bytes;
		is_last    = 1;
	} else {
		chunk_size = MAX_BUFFER;
	}

	char *read_buf = safe_malloc(chunk_size);

	if (lseek(current_job->filefd, current_job->beginning, SEEK_SET) == -1) {
		perror("Error seeking in file, closing client connection");
		free(read_buf);
		return -1;
	}

	ssize_t read_length = read(current_job->filefd, read_buf, chunk_size);
	if (read_length <= 0) {
		if (read_length == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				free(read_buf);
				return 0;
			}
			perror("Error while reading file");
		} else {
			printf("The read file is smaller than expected\n");
		}
		free(read_buf);
		return -1;
	}

	size_t sent = socket_send(current_job->clientfd, read_buf, read_length);

	free(read_buf);

	if (sent < (size_t)read_length) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			current_job->beginning += sent;
			return 0;
		}
		return -1;
	}
	if (is_last) {
		return -1;
	}

	current_job->beginning += sent;

	return 0;
}

/*
 * From the passed headers checks if jwt passed in the 'Authorization' header is
 * valid by validating the signature with the passed pubkey and the expiration.
 * If the request_mode is REQUEST_USER it will not check additional values in
 * the payload, if it is REQUEST_ADMIN the validation will require a
 * "admin:true" field to succeed. The pubkey can be null whenever it hasn't been
 * configured, in this case the authorization will always be accepted
 * returns: 0 if the authorization is rejected, 1 if the authorization is
 * accepted
 */
int is_jwt_valid(char *headers, const int headers_len, const int request_mode,
                 const char *pubkey) {
	if (!pubkey) return 1;
	char *authorization =
	    find_http_header_value(headers, headers_len, "Authorization");
	if (authorization == NULL) {
		return 0;
	}
	char *token = strtok(authorization, " ");
	if (token == NULL) {
		free(authorization);
		return 0;
	}
	token = strtok(NULL, " ");
	if (token == NULL) {
		free(authorization);
		return 0;
	}
	char *header_end = strchr(token, '.');
	if (header_end == NULL) {
		free(authorization);
		return 0;
	}
	char *payload_end = strchr(header_end + 1, '.');
	if (payload_end == NULL) {
		free(authorization);
		return 0;
	}
	size_t sig_start = payload_end - token + 1;

	size_t         sig_len;
	unsigned char *signature =
	    base64url_decode(token + sig_start, strlen(token + sig_start), &sig_len);

	if (signature == NULL) {
		free(authorization);
		return 0;
	}
	size_t         pubkey_len;
	unsigned char *pubkey_raw =
	    base64url_decode(pubkey, strlen(pubkey), &pubkey_len);
	if (pubkey_raw == NULL) {
		free(signature);
		free(authorization);
		return 0;
	}
	EVP_PKEY *pkey  = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
	                                              pubkey_raw, pubkey_len);

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL || !EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey)) {
		printf("Error in POST request digest verify init\n");
		if (ctx) EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		free(authorization);
		free(signature);
		free(pubkey_raw);
		return 0;
	}

	size_t message_len = payload_end - token;
	int    result      = EVP_DigestVerify(ctx, signature, sig_len,
	                                      (unsigned char *)token, message_len);

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	free(signature);
	free(pubkey_raw);

	if (result != 1) {
		if (result == 0) {
			printf("POST request received with invalid jwt "
			       "signature\n");
		} else {
			printf("POST request received with invalid jwt "
			       "signature: Error %lo\n",
			       ERR_get_error());
		}
		free(authorization);
		return 0;
	}

	// Decode payload
	size_t payload_len = payload_end - (header_end + 1);
	*payload_end       = '\0';
	size_t         decoded_payload_len;
	unsigned char *decoded_payload =
	    base64url_decode(header_end + 1, payload_len, &decoded_payload_len);
	*payload_end = '.';

	if (decoded_payload == NULL) {
		printf("Failed to decode JWT payload\n");
		free(authorization);
		return 0;
	}

	// JWT parsing
	char *payload_json = safe_malloc(decoded_payload_len + 1);
	memcpy(payload_json, decoded_payload, decoded_payload_len);
	payload_json[decoded_payload_len] = '\0';
	free(decoded_payload);

	int isAdmin = 0;
	if (request_mode == REQUEST_ADMIN) {
		// JWT Admin check
		char *admin_str = strstr(payload_json, "\"admin\"");
		if (admin_str != NULL) {
			admin_str = strchr(admin_str, ':');
			if (admin_str != NULL) {
				if (strncmp(admin_str + 1, "true", 4) == 0) {
					isAdmin = 1;
				}
			}
		}
	}

	// JWT expiration check
	char  *exp_str  = strstr(payload_json, "\"exp\"");
	time_t exp_time = 0;
	if (exp_str != NULL) {
		exp_str = strchr(exp_str, ':');
		if (exp_str != NULL) {
			exp_time = atoll(exp_str + 1);
		}
	}

	free(payload_json);
	free(authorization);

	if (exp_time == 0) {
		printf("JWT missing exp field\n");
		return 0;
	}

	time_t current_time = time(NULL);
	if (current_time >= exp_time) {
		printf("JWT expired (exp: %ld, now: %ld)\n", exp_time, current_time);
		return 0;
	}

	if (request_mode == REQUEST_ADMIN && !isAdmin) {
		printf("User is not admin!\n");
		return 0;
	}
	return 1;
}

/*
 * Finds the requested http path from passed request of request_len size
 * returns: the found path, null if not found or an error occurred
 */
char *find_request_path(const char *request, const unsigned int request_len) {
	char *temp = safe_malloc(request_len + 1);

	memcpy(temp, request, request_len);
	temp[request_len] = '\0';

	char *path        = safe_malloc(256);
	int   result      = sscanf(temp, "%*s %255s", path);
	free(temp);
	if (result == 0 || result == EOF) {
		perror("Error in path scan");
		free(path);
		return NULL;
	}
	return path;
}

/*
 * Starts listening clients for http requests and handles every client.
 * returns: 0 if the server has been successfully closed (with SIGINT), -1 for
 * errors
 */
int start_http_server(fise *data) {
	data->events = (struct epoll_event *)safe_malloc(MAX_EVENTS *
	                                                 sizeof(struct epoll_event));

	if (socket_start_listener(data->sockfd, &data->epfd) == -1) return -1;
	signal(SIGINT, intHandler);
	printf("Server started! Press 'ctrl+c' to shut it down.\n");
	while (running) {
		int n_events = epoll_wait(data->epfd, data->events, MAX_EVENTS, 10);

		if (n_events == -1) {
			if (!running) break;
			perror("Error while reading events");
		}

		// READ NEW EVENTS
		for (int i = 0; i < n_events; i++) {
			if (data->events[i].data.fd == data->sockfd) {
				// The event is that a new client has connected to the socket,
				// so an accept is needed instead of read
				while (1) {
					struct sockaddr peeraddr;
					socklen_t       addr_len = sizeof(peeraddr);
					int acceptfd = accept(data->sockfd, &peeraddr, &addr_len);

					if (acceptfd == -1) {
						if (errno == EAGAIN) {
							// There isn't nothing to accept anymore
							break;
						}
						perror("Error while accepting connection");
						continue;
					} else {
						int flags = fcntl(acceptfd, F_GETFL, 0);
						if (flags == -1) {
							perror("Error getting socket flags");
							close(acceptfd);
							continue;
						}
						if (fcntl(acceptfd, F_SETFL, flags | O_NONBLOCK) == -1) {
							perror("fcntl F_SETFL");
							close(acceptfd);
							continue;
						}

						struct epoll_event *acceptfd_event =
						    (struct epoll_event *)safe_malloc(
						        sizeof(struct epoll_event));
						acceptfd_event->events    = EPOLLIN;
						acceptfd_event->data.fd   = acceptfd;
						job *clientJob            = (job *)safe_malloc(sizeof(job));
						clientJob->headers_len    = 0;
						clientJob->body_chunk_len = 0;
						clientJob->status         = STATUS_IDLE;
						clientJob->clientfd       = acceptfd;
						clientJob->filefd         = -1;
						clientJob->id             = NULL;

						add_job(data, clientJob);

						if (epoll_ctl(data->epfd, EPOLL_CTL_ADD, acceptfd,
						              acceptfd_event) == -1) {
							perror("Error while adding the peer to events listener");
							if (close(acceptfd) == -1) {
								perror("Error while closing connection");
							}
							clientJob->status = STATUS_DISCONNECTED;
						}
						free(clientJob);
						free(acceptfd_event);
					}
				}
				continue;
			}
			job *current_job = find_client_job(data, data->events[i].data.fd);
			if (current_job == NULL) {
				printf("Client job not found!\n");
				continue;
			}
			if (data->events[i].events & EPOLLIN) {
				// Socket has data to read
				char   *read_buf = (char *)safe_malloc(MAX_BUFFER);
				ssize_t buf_len = read(current_job->clientfd, read_buf, MAX_BUFFER);
				if (buf_len == -1) {
					perror("Error while reading socket message");
					free(read_buf);
					continue;
				}
				if (buf_len == 0) {
					printf("Remote peer closed the connection\n");
					free(read_buf);
					disconnect_client(data->epfd, current_job);
					continue;
				}
				if (current_job->status == STATUS_IDLE) {
					current_job->status = STATUS_SENDING_HEADERS;
				}
				if (current_job->status == STATUS_SENDING_HEADERS) {
					if (current_job->headers_len == 0) {
						current_job->headers = safe_malloc(buf_len);
					} else {
						current_job->headers = safe_realloc(
						    current_job->headers, current_job->headers_len + buf_len);
					}
					memcpy(current_job->headers + current_job->headers_len, read_buf,
					       buf_len);
					current_job->headers_len += (unsigned int)buf_len;

					char *headers_end =
					    memmem(current_job->headers, current_job->headers_len,
					           "\r\n\r\n", 4);
					if (headers_end != NULL) {
						headers_end += 4;
						if (headers_end <=
						    current_job->headers + current_job->headers_len - 1) {
							// After \r\n\r\n a body have been detected, so the headers
							// finish earlier than headers_len
							unsigned int headers_body_len = current_job->headers_len;
							current_job->headers_len =
							    headers_end - current_job->headers;

							unsigned long body_chunk_len =
							    headers_body_len - current_job->headers_len;
							current_job->body_chunk     = safe_malloc(body_chunk_len);
							current_job->body_chunk_len = body_chunk_len;
							memcpy(current_job->body_chunk, headers_end,
							       body_chunk_len);
						}
						free(read_buf);
						current_job->status = STATUS_IDLE;
					} else {
						// The user have more headers to send
						free(read_buf);
						if (current_job->headers_len > HEADERS_MAX_SIZE) {
							// The headers size are too big
							disconnect_client(data->epfd, current_job);
						}
						continue;
					}
				}
				if (current_job->status == STATUS_UPLOADING) {
					if (current_job->body_chunk_len > 0) {
						free(current_job->body_chunk);
					}
					current_job->body_chunk     = read_buf;
					current_job->body_chunk_len = buf_len;
				}
				if (current_job->status == STATUS_IDLE) {
					/* The client doesn't have a job yet, try initializing one or
					 * close the connection */
					if (strncmp("GET", current_job->headers, 3) == 0) {
						/* The user want to download or only check the / page to see
						 * if it is alive */

						// Check path
						char *path = find_request_path(current_job->headers,
						                               current_job->headers_len);

						if (!path) {
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Bad request");
							disconnect_client(data->epfd, current_job);
							continue;
						}

						char *segment = strtok(path, "/");
						if (segment == NULL) {
							free(path);
							path = NULL;
							http_send_response(current_job->clientfd, "200", NULL,
							                   "alive");
							disconnect_client(data->epfd, current_job);
							continue;
						}

						if (strcmp(segment, "api") == 0) {
							segment = strtok(NULL, "/");
							if (segment == NULL) {
								free(path);
								path = NULL;
								http_send_response(current_job->clientfd, "404", NULL,
								                   "Not found");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							if (strchr(segment, '.') != NULL ||
							    strchr(segment, '/') != NULL || strlen(segment) == 0 ||
							    strlen(segment) > 255) {
								free(path);
								path = NULL;
								http_send_response(current_job->clientfd, "403", NULL,
								                   "Forbidden");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							char dir_path[strlen(FILES_PATH) + strlen(segment) + 1];
							long path_len = snprintf(dir_path, sizeof(dir_path),
							                         "%s%s", FILES_PATH, segment);
							free(path);
							path = NULL;
							if (path_len < 0) {
								perror("Error in GET file path calculation");
								http_send_response(current_job->clientfd, "400", NULL,
								                   "Bad request");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							if (path_len >= (long)sizeof(dir_path)) {
								printf(
								    "Error in GET file path calculation, the size of "
								    "path_len is too big!\n");
								http_send_response(current_job->clientfd, "500", NULL,
								                   "Please contact an administrator");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							char *real_path = realpath(dir_path, NULL);
							if (real_path == NULL) {
								perror("Error while evaluating real path");
								http_send_response(current_job->clientfd, "404", NULL,
								                   "File not found");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							if (strncmp(real_path, FILES_PATH, strlen(FILES_PATH)) !=
							    0) {
								free(real_path);
								http_send_response(current_job->clientfd, "403", NULL,
								                   "Forbidden");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							DIR *dir = opendir(real_path);
							if (dir == NULL) {
								free(real_path);
								perror(
								    "Error while opening the requested api directory");
								http_send_response(current_job->clientfd, "404", NULL,
								                   "Not found");
								disconnect_client(data->epfd, current_job);
								continue;
							}

							struct dirent *entry;
							int            filefd    = -1;
							char          *file_name = NULL;
							while ((entry = readdir(dir)) != NULL) {
								if (strcmp(entry->d_name, ".") == 0 ||
								    strcmp(entry->d_name, "..") == 0) {
									continue;
								}
								// Build full path
								char file_path[PATH_MAX];
								snprintf(file_path, sizeof(file_path), "%s/%s",
								         real_path, entry->d_name);

								struct stat st;
								int         attributes = stat(file_path, &st);
								if (attributes == -1) {
									perror("Stat error");
									continue;
								}
								// Check if it's a regular file
								if (attributes == 0 && S_ISREG(st.st_mode)) {
									// Open the first regular file found
									filefd    = open(file_path, O_RDONLY | O_NONBLOCK);
									file_name = strdup(entry->d_name);
									if (filefd == -1) {
										perror("Failed to open file");
									}
									break;
								}
							}
							free(real_path);

							if (closedir(dir) == -1) {
								perror("Error while closing file directory");
							}

							if (file_name == NULL) {
								http_send_response(current_job->clientfd, "404", NULL,
								                   "Not found");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							if (filefd == -1) {
								http_send_response(current_job->clientfd, "404", NULL,
								                   "Not found");
								disconnect_client(data->epfd, current_job);
								free(file_name);
								continue;
							}
							current_job->filefd = filefd;
							struct stat file_stat;
							if (fstat(filefd, &file_stat) == -1) {
								perror("Fstat error");
								close(filefd);
								free(file_name);
								http_send_response(current_job->clientfd, "500", NULL,
								                   "Please contact an administrator");
								disconnect_client(data->epfd, current_job);
								continue;
							}

							char *range = find_http_header_value(
							    current_job->headers, current_job->headers_len,
							    "Range");

							int disp_header_len = snprintf(
							    NULL, 0, "attachment; filename=\"%s\"", file_name);
							if (disp_header_len <= 0) {
								http_send_response(current_job->clientfd, "500", NULL,
								                   "Please contact an administrator");
								disconnect_client(data->epfd, current_job);
								free(file_name);
								continue;
							}
							char disp_header[disp_header_len];
							if (sprintf(disp_header, "attachment; filename=\"%s\"",
							            file_name) < 0) {
								perror("sprintf");
								http_send_response(current_job->clientfd, "500", NULL,
								                   "Please contact an administrator");
								disconnect_client(data->epfd, current_job);
								free(file_name);
								continue;
							}
							free(file_name);

							if (range != NULL) {
								char    unit[32];
								ssize_t start, end;

								if (sscanf(range, "%[^=]=%ld-%ld", unit, &start,
								           &end) == 3) {
									// Range with both start and end
									current_job->beginning = start;
									current_job->end       = end;
								} else if (sscanf(range, "%[^=]=%ld-", unit, &start) ==
								           2) {
									// Range from start to end of file
									current_job->beginning = start;
									current_job->end       = file_stat.st_size - 1;
								} else {
									// Range invalid, send from beginning
									current_job->beginning = 0;
									current_job->end       = file_stat.st_size - 1;
								}
								free(range);
								if (current_job->end < current_job->beginning) {
									// The size of start is smaller than end, so they
									// need to be swapped to prevent errors
									ssize_t temp_end       = current_job->end;
									current_job->end       = current_job->beginning;
									current_job->beginning = temp_end;
								}
								// Send the head, leave the rest of the job to the job
								// queue
								long content_length = (long)current_job->end + 1 -
								                      (long)current_job->beginning;
								long content_range_end = (long)current_job->end;
								long content_range_beginning =
								    (long)current_job->beginning;
								long content_range_size = (long)file_stat.st_size;

								int range_header_len =
								    snprintf(NULL, 0, "bytes %ld-%ld/%ld",
								             content_range_beginning, content_range_end,
								             content_range_size);
								if (range_header_len <= 0) {
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}
								char range_header[range_header_len];
								if (sprintf(range_header, "bytes %ld-%ld/%ld",
								            content_range_beginning, content_range_end,
								            content_range_size) < 0) {
									perror("sprintf");
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}

								int content_header_len =
								    snprintf(NULL, 0, "%ld", content_length);
								if (content_header_len <= 0) {
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}
								char content_header[content_header_len];
								if (sprintf(content_header, "%ld", content_length) <
								    0) {
									perror("sprintf");
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}

								header_node *headers = create_headers(
								    "Content-Type,Content-Length,Content-Range,"
								    "Content-"
								    "Disposition",
								    "application/octet-stream; charset=UTF-8",
								    content_header, range_header, disp_header);
								if (http_send_response(current_job->clientfd, "206",
								                       headers, NULL) == -1) {
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}
							} else {
								// Range not requested, send from beginning
								current_job->beginning = 0;
								current_job->end       = file_stat.st_size - 1;

								// Send the head, leave the rest of the job to the job
								// queue
								long content_length = (long)file_stat.st_size;

								int content_header_len =
								    snprintf(NULL, 0, "%ld", content_length);
								if (content_header_len <= 0) {
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}
								char content_header[content_header_len];
								if (sprintf(content_header, "%ld", content_length) <
								    0) {
									perror("sprintf");
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}
								header_node *headers = create_headers(
								    "Content-Type,Content-Length,"
								    "Content-"
								    "Disposition",
								    "application/octet-stream; charset=UTF-8",
								    content_header, disp_header);
								if (http_send_response(current_job->clientfd, "200",
								                       headers, NULL) == -1) {
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}
							}
							current_job->status = STATUS_DOWNLOADING;
							struct epoll_event mod_event;
							mod_event.events  = EPOLLOUT;
							mod_event.data.fd = current_job->clientfd;

							if (epoll_ctl(data->epfd, EPOLL_CTL_MOD,
							              current_job->clientfd, &mod_event) == -1) {
								perror("Error modifying epoll events for download");
								http_send_response(current_job->clientfd, "500", NULL,
								                   "Please contact an administrator");
								disconnect_client(data->epfd, current_job);
								continue;
							}
						} else {
							// Path segment is not "api", invalid request
							free(path);
							path = NULL;
							http_send_response(current_job->clientfd, "404", NULL,
							                   "Not found");
							disconnect_client(data->epfd, current_job);
							continue;
						}
					} else if (strncmp("POST", current_job->headers, 4) == 0) {
						// The user want to upload
						if (!is_jwt_valid(current_job->headers,
						                  current_job->headers_len, REQUEST_USER,
						                  data->pubkey)) {
							http_send_response(current_job->clientfd, "401", NULL,
							                   "Unauthorized");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						// Verify Content Length
						char *content_length_str = find_http_header_value(
						    current_job->headers, current_job->headers_len,
						    "Content-Length");
						if (content_length_str == NULL) {
							// The user didn't send the file length
							printf("The user didn't send the file length\n");
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Content-Length not found");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						long content_length = atol(content_length_str);
						free(content_length_str);
						if (content_length <= 0 || content_length > MAX_UPLOAD_SIZE) {
							// The user sent an invalid file length or it exceeds the
							// max upload size
							printf("The user sent invalid file length\n");
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid content length or too large");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						current_job->upload_size = content_length;

						// Generate random uuid folder
						uuid_t binuuid;
						uuid_generate(binuuid);
						char *uuid = safe_malloc(37);
						uuid_unparse_lower(binuuid, uuid);

						char *uuid_path =
						    safe_malloc(strlen(FILES_PATH) + strlen(uuid) + 1);
						if (sprintf(uuid_path, "%s%s", FILES_PATH, uuid) < 0) {
							perror("sprintf");
							free(uuid);
							free(uuid_path);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (mkdir(uuid_path, S_IRWXU) == -1) {
							perror("mkdir");
							free(uuid_path);
							free(uuid);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						char *content_disposition = find_http_header_value(
						    current_job->headers, current_job->headers_len,
						    "Content-Disposition");
						if (!content_disposition) {
							rmdir(uuid_path);
							free(uuid_path);
							free(uuid);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Content-Disposition not found");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						strtok(content_disposition, "=");
						char *filename = strtok(NULL, "=");
						if (!filename || strlen(filename) == 0 ||
						    strlen(filename) > 255) {
							rmdir(uuid_path);
							free(uuid_path);
							free(uuid);
							free(content_disposition);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid content disposition");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (strstr(filename, "..") != NULL ||
						    strchr(filename, '/') != NULL) {
							rmdir(uuid_path);
							free(uuid_path);
							free(uuid);
							free(content_disposition);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid content disposition");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						char *file_path =
						    safe_malloc(strlen(uuid_path) + 1 + strlen(filename) + 1);
						int sprintf_result =
						    sprintf(file_path, "%s/%s", uuid_path, filename);
						free(content_disposition);
						if (sprintf_result < 0) {
							perror("sprintf");
							rmdir(uuid_path);
							free(uuid_path);
							free(uuid);
							free(file_path);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						int filefd =
						    open(file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
						free(file_path);
						if (filefd == -1) {
							perror("open");
							// Clean up the empty directory
							rmdir(uuid_path);
							free(uuid_path);
							free(uuid);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						free(uuid_path);
						current_job->id             = uuid;
						current_job->filefd         = filefd;
						current_job->status         = STATUS_UPLOADING;
						current_job->uploaded_bytes = 0;

						struct epoll_event mod_event;
						mod_event.events  = EPOLLIN;
						mod_event.data.fd = current_job->clientfd;

						if (epoll_ctl(data->epfd, EPOLL_CTL_MOD,
						              current_job->clientfd, &mod_event) == -1) {
							perror("Error modifying epoll events for download");
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
					} else if (strncmp("OPTIONS", current_job->headers, 7) == 0) {
						http_send_response(current_job->clientfd, "200", NULL, NULL);
						disconnect_client(data->epfd, current_job);
					} else if (strncmp("DELETE", current_job->headers, 6) == 0) {
						if (!is_jwt_valid(current_job->headers,
						                  current_job->headers_len, REQUEST_ADMIN,
						                  data->pubkey)) {
							http_send_response(current_job->clientfd, "401", NULL,
							                   "Unauthorized");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						char *id = find_http_header_value(current_job->headers,
						                                  current_job->headers_len,
						                                  "X-FILE-ID");
						if (id == NULL) {
							http_send_response(current_job->clientfd, "400", NULL,
							                   "X-FILE-ID not found");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (strlen(id) > 255) {
							free(id);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid X-FILE-ID");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (strstr(id, "..") != NULL || strchr(id, '/') != NULL) {
							free(id);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid X-FILE-ID");
							disconnect_client(data->epfd, current_job);
							continue;
						}

						int  path_len = snprintf(NULL, 0, "%s%s", FILES_PATH, id) + 1;
						char path[path_len];
						if (snprintf(path, path_len, "%s%s", FILES_PATH, id) < 0) {
							perror("sprintf");
							free(id);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (remove_directory(path) != 0) {
							perror("Error while deleting file");
							free(id);
							http_send_response(current_job->clientfd, "404", NULL,
							                   "File ID not found");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						current_job->id     = id;
						current_job->status = STATUS_WAITING_UPLOAD_ID;
						struct epoll_event mod_event;
						mod_event.events  = EPOLLOUT;
						mod_event.data.fd = current_job->clientfd;

						if (epoll_ctl(data->epfd, EPOLL_CTL_MOD,
						              current_job->clientfd, &mod_event) == -1) {
							perror("Error modifying epoll events for download");
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
					} else {
						// The user did not send a valid message, closing the
						// connection
						disconnect_client(data->epfd, current_job);
						continue;
					}
				}
				if (current_job->status == STATUS_UPLOADING) {
					size_t  total_written = 0;
					ssize_t written       = -1;
					while (total_written < current_job->body_chunk_len) {
						written = write(current_job->filefd,
						                current_job->body_chunk + total_written,
						                current_job->body_chunk_len - total_written);
						if (written == -1) {
							perror("Error while writing received file data chunk");
							disconnect_client(data->epfd, current_job);
							break;
						}
						total_written += written;
					}
					if (written == -1) {
						continue;
					}
					current_job->uploaded_bytes += total_written;
					if (current_job->uploaded_bytes == current_job->upload_size) {
						// The user finished uploading
						struct epoll_event mod_event;
						mod_event.events  = EPOLLOUT;
						mod_event.data.fd = current_job->clientfd;

						if (epoll_ctl(data->epfd, EPOLL_CTL_MOD,
						              current_job->clientfd, &mod_event) == -1) {
							perror("Error modifying epoll events for upload");
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						current_job->status = STATUS_WAITING_UPLOAD_ID;
					} else if (current_job->uploaded_bytes >
					           current_job->upload_size) {
						// The user sent more data than expected
						char uuid_path[strlen(FILES_PATH) + strlen(current_job->id) +
						               1];
						if (sprintf(uuid_path, "%s%s", FILES_PATH, current_job->id) <
						    0) {
							perror("sprintf");
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						rmdir(uuid_path);
						http_send_response(current_job->clientfd, "400", NULL,
						                   "More data than expected received");
						printf("User sent more data than expected\n");
						disconnect_client(data->epfd, current_job);
						continue;
					}
				}
			}
			if (data->events[i].events & EPOLLOUT) {
				// Socket is ready for write
				if (current_job->status == STATUS_DOWNLOADING) {
					if (process_download_chunk(current_job) == -1) {
						disconnect_client(data->epfd, current_job);
						continue;
					}
					continue;
				}
				if (current_job->status == STATUS_WAITING_UPLOAD_ID) {
					http_send_response(current_job->clientfd, "201", NULL,
					                   current_job->id);
					disconnect_client(data->epfd, current_job);
					continue;
				}
			}
		}
	}
	printf("\nServer shutting down...\n");
	return 0;
}

/*
 * Creates the passed dir directory if not already exists
 * returns: 0 for success, -1 for error
 */
int create_folder(const char *dir) {
	struct stat st = {0};
	if (stat(dir, &st) == -1) {
		if (errno == ENOENT) {
			char   tmp[PATH_MAX];
			char  *p = NULL;
			size_t len;

			snprintf(tmp, sizeof(tmp), "%s", dir);
			len = strlen(tmp);
			if (tmp[len - 1] == '/') tmp[len - 1] = 0;
			for (p = tmp + 1; *p; p++)
				if (*p == '/') {
					*p = 0;
					if (mkdir(tmp, S_IRWXU) == -1 && errno != EEXIST) {
						printf("Error while creating directory %s: %s", dir,
						       strerror(errno));
						return -1;
					}
					*p = '/';
				}
			if (mkdir(tmp, S_IRWXU) == -1 && errno != EEXIST) {
				printf("Error while creating directory %s: %s", dir,
				       strerror(errno));
				return -1;
			}
			return 0;
		}
	}
	return 0;
}

/*
 * Creates an empty file at the passed path if not already exists
 * returns: 0 for success, -1 for error
 */
int create_file(const char *path) {
	struct stat st;
	if (stat(path, &st) == -1) {
		FILE *file = fopen(path, "w");
		if (file == NULL) {
			printf("Error while creating file %s: %s", path, strerror(errno));
			return -1;
		}
		fclose(file);
	}
	return 0;
}

int main(void) {
	if (create_folder(FILES_PATH) == -1) {
		return 1;
	}
	if (create_folder(CONFIG_PATH) == -1) {
		return 1;
	}
	if (create_file(PUBKEY_PATH) == -1) {
		return 1;
	}
	fise *data = (fise *)safe_malloc(sizeof(fise));
	if (create_http_server(data, "0.0.0.0", 80) == -1) {
		close_socket(data);
		return 1;
	}
	int res = start_http_server(data);
	close_socket(data);
	if (res == -1) {
		return 1;
	}
	return 0;
}
