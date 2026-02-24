// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#include "server.h"
#include "files.h"
#include "http.h"
#include "jwt.h"
#include "mem.h"
#include "socket.h"
#include "str.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
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
#define MAX_BUFFER                                                             \
	4 * 1024 * 1024 // 4 MB. The maximum the server/client can read or
	                // write withone call (not always applied by the server in
	                // write when the response is not too large)
#define MAX_EVENTS 100

static volatile int running = 1;

void intHandler(int sig) {
	if (sig == SIGINT) running = 0;
}

/*
 * Initializes the members of data and creates the socket at 'addr' address and
 * 'port' port
 * returns: 0 for success, -1 for error
 */
int create_http_server(fise *data, const char *addr, const uint16_t port) {
	data->addr   = (struct sockaddr_in *)smalloc(sizeof(struct sockaddr_in));
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
				sfree(line);
			}
		} else if (line != NULL) {
			sfree(line);
		}
		fclose(pubkey_file);
	}
	return create_socket(addr, port, data->addr, &data->sockfd);
}

/*
 * Closes server's file descriptors and frees non-null memory
 */
void close_server(fise *data) {
	if (data->addr) {
		sfree(data->addr);
	}
	if (data->events) {
		sfree(data->events);
	}
	if (data->jobs) {
		sfree(data->jobs);
	}
	if (data->pubkey) {
		sfree(data->pubkey);
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
	sfree(data);
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
	job   *new_jobs = srealloc(data->jobs, (job_size * data->n_jobs));
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
		sfree(current_job->headers);
		current_job->headers     = NULL;
		current_job->headers_len = 0;
	}
	if (current_job->body_chunk_len > 0) {
		sfree(current_job->body_chunk);
		current_job->body_chunk     = NULL;
		current_job->body_chunk_len = 0;
	}
	if ((current_job->status == STATUS_UPLOADING ||
	     current_job->status == STATUS_WAITING_UPLOAD_ID) &&
	    current_job->id) {
		sfree(current_job->id);
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

	char *read_buf = smalloc(chunk_size);

	if (lseek(current_job->filefd, current_job->beginning, SEEK_SET) == -1) {
		perror("Error seeking in file, closing client connection");
		sfree(read_buf);
		return -1;
	}

	ssize_t read_length = read(current_job->filefd, read_buf, chunk_size);
	if (read_length <= 0) {
		if (read_length == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				sfree(read_buf);
				return 0;
			}
			perror("Error while reading file");
		} else {
			printf("The read file is smaller than expected\n");
		}
		sfree(read_buf);
		return -1;
	}

	size_t sent = socket_send(current_job->clientfd, read_buf, read_length);

	sfree(read_buf);

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
 * Finds the requested http path from passed request of request_len size
 * returns: the found path, null if not found or an error occurred
 */
char *find_request_path(const char *request, const unsigned int request_len) {
	char *temp = smalloc(request_len + 1);

	memcpy(temp, request, request_len);
	temp[request_len] = '\0';

	char *path        = smalloc(256);
	int   result      = sscanf(temp, "%*s %255s", path);
	sfree(temp);
	if (result == 0 || result == EOF) {
		perror("Error in path scan");
		sfree(path);
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
	data->events =
	    (struct epoll_event *)smalloc(MAX_EVENTS * sizeof(struct epoll_event));

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
						    (struct epoll_event *)smalloc(sizeof(struct epoll_event));
						acceptfd_event->events    = EPOLLIN;
						acceptfd_event->data.fd   = acceptfd;
						job *clientJob            = (job *)smalloc(sizeof(job));
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
						sfree(clientJob);
						sfree(acceptfd_event);
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
				char   *read_buf = (char *)smalloc(MAX_BUFFER);
				ssize_t buf_len = read(current_job->clientfd, read_buf, MAX_BUFFER);
				if (buf_len == -1) {
					perror("Error while reading socket message");
					sfree(read_buf);
					continue;
				}
				if (buf_len == 0) {
					printf("Remote peer closed the connection\n");
					sfree(read_buf);
					disconnect_client(data->epfd, current_job);
					continue;
				}
				if (current_job->status == STATUS_IDLE) {
					current_job->status = STATUS_SENDING_HEADERS;
				}
				if (current_job->status == STATUS_SENDING_HEADERS) {
					if (current_job->headers_len == 0) {
						current_job->headers = smalloc(buf_len);
					} else {
						current_job->headers = srealloc(
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
							current_job->body_chunk     = smalloc(body_chunk_len);
							current_job->body_chunk_len = body_chunk_len;
							memcpy(current_job->body_chunk, headers_end,
							       body_chunk_len);
						}
						sfree(read_buf);
						current_job->status = STATUS_IDLE;
					} else {
						// The user have more headers to send
						sfree(read_buf);
						if (current_job->headers_len > HEADERS_MAX_SIZE) {
							// The headers size are too big
							disconnect_client(data->epfd, current_job);
						}
						continue;
					}
				}
				if (current_job->status == STATUS_UPLOADING) {
					if (current_job->body_chunk_len > 0) {
						sfree(current_job->body_chunk);
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
							sfree(path);
							path = NULL;
							http_send_response(current_job->clientfd, "200", NULL,
							                   "alive");
							disconnect_client(data->epfd, current_job);
							continue;
						}

						if (strcmp(segment, "api") == 0) {
							segment = strtok(NULL, "/");
							if (segment == NULL) {
								sfree(path);
								path = NULL;
								http_send_response(current_job->clientfd, "404", NULL,
								                   "Not found");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							if (strchr(segment, '.') != NULL ||
							    strchr(segment, '/') != NULL || strlen(segment) == 0 ||
							    strlen(segment) > 255) {
								sfree(path);
								path = NULL;
								http_send_response(current_job->clientfd, "403", NULL,
								                   "Forbidden");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							char dir_path[strlen(FILES_PATH) + strlen(segment) + 1];
							long path_len = snprintf(dir_path, sizeof(dir_path),
							                         "%s%s", FILES_PATH, segment);
							sfree(path);
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
								sfree(real_path);
								http_send_response(current_job->clientfd, "403", NULL,
								                   "Forbidden");
								disconnect_client(data->epfd, current_job);
								continue;
							}
							int   filefd    = -1;
							char *file_name = open_first(real_path, &filefd);

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
								sfree(file_name);
								continue;
							}
							current_job->filefd = filefd;
							struct stat file_stat;
							if (fstat(filefd, &file_stat) == -1) {
								perror("Fstat error");
								close(filefd);
								sfree(file_name);
								http_send_response(current_job->clientfd, "500", NULL,
								                   "Please contact an administrator");
								disconnect_client(data->epfd, current_job);
								continue;
							}

							char *range = find_http_header_value(
							    current_job->headers, current_job->headers_len,
							    "Range");

							char *disp_header =
							    new_str("attachment; filename=\"%s\"", file_name);
							sfree(file_name);
							if (!disp_header) {
								http_send_response(current_job->clientfd, "500", NULL,
								                   "Please contact an administrator");
								disconnect_client(data->epfd, current_job);
								continue;
							}

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
								sfree(range);
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

								char *range_header      = new_str(
                            "bytes %ld-%ld/%ld", content_range_beginning,
                            content_range_end, content_range_size);
								if (!range_header) {
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}

								char *content_header = new_str("%ld", content_length);
								if (!content_header) {
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
								}

								header_node *headers = create_headers(
								    "Content-Type,Content-Length,Content-Range,"
								    "Content-"
								    "Disposition",
								    "application/octet-stream; charset=UTF-8",
								    content_header, range_header, disp_header);
								if (http_send_response(current_job->clientfd, "206",
								                       headers, NULL) == -1) {
									sfree(disp_header);
									sfree(range_header);
									sfree(content_header);
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}
								sfree(disp_header);
								sfree(range_header);
								sfree(content_header);
							} else {
								// Range not requested, send from beginning
								current_job->beginning = 0;
								current_job->end       = file_stat.st_size - 1;

								// Send the head, leave the rest of the job to the job
								// queue
								long  content_length = (long)file_stat.st_size;
								char *content_header = new_str("%ld", content_length);
								if (!content_header) {
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
								}
								header_node *headers = create_headers(
								    "Content-Type,Content-Length,"
								    "Content-"
								    "Disposition",
								    "application/octet-stream; charset=UTF-8",
								    content_header, disp_header);
								if (http_send_response(current_job->clientfd, "200",
								                       headers, NULL) == -1) {
									sfree(disp_header);
									sfree(content_header);
									http_send_response(
									    current_job->clientfd, "500", NULL,
									    "Please contact an administrator");
									disconnect_client(data->epfd, current_job);
									continue;
								}
								sfree(disp_header);
								sfree(content_header);
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
							sfree(path);
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
						sfree(content_length_str);
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
						char *uuid = smalloc(37);
						uuid_unparse_lower(binuuid, uuid);

						char *uuid_path =
						    smalloc(strlen(FILES_PATH) + strlen(uuid) + 1);
						if (sprintf(uuid_path, "%s%s", FILES_PATH, uuid) < 0) {
							perror("sprintf");
							sfree(uuid);
							sfree(uuid_path);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (create_dir(uuid_path) == -1) {
							perror("create_dir");
							sfree(uuid_path);
							sfree(uuid);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						char *content_disposition = find_http_header_value(
						    current_job->headers, current_job->headers_len,
						    "Content-Disposition");
						if (!content_disposition) {
							remove_dir(uuid_path);
							sfree(uuid_path);
							sfree(uuid);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Content-Disposition not found");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						strtok(content_disposition, "=");
						char *filename = strtok(NULL, "=");
						if (!filename || strlen(filename) == 0 ||
						    strlen(filename) > 255) {
							remove_dir(uuid_path);
							sfree(uuid_path);
							sfree(uuid);
							sfree(content_disposition);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid content disposition");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (strstr(filename, "..") != NULL ||
						    strchr(filename, '/') != NULL) {
							remove_dir(uuid_path);
							sfree(uuid_path);
							sfree(uuid);
							sfree(content_disposition);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid content disposition");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						char *file_path =
						    smalloc(strlen(uuid_path) + 1 + strlen(filename) + 1);
						int sprintf_result =
						    sprintf(file_path, "%s/%s", uuid_path, filename);
						sfree(content_disposition);
						if (sprintf_result < 0) {
							perror("sprintf");
							remove_dir(uuid_path);
							sfree(uuid_path);
							sfree(uuid);
							sfree(file_path);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						int filefd =
						    open(file_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
						sfree(file_path);
						if (filefd == -1) {
							perror("open");
							// Clean up the empty directory
							remove_dir(uuid_path);
							sfree(uuid_path);
							sfree(uuid);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						sfree(uuid_path);
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
							sfree(id);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid X-FILE-ID");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (strstr(id, "..") != NULL || strchr(id, '/') != NULL) {
							sfree(id);
							http_send_response(current_job->clientfd, "400", NULL,
							                   "Invalid X-FILE-ID");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						char *path = new_str("%s%s", FILES_PATH, id);
						if (!path) {
							sfree(id);
							http_send_response(current_job->clientfd, "500", NULL,
							                   "Please contact an administrator");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						if (remove_dir(path) != 0) {
							perror("Error while deleting file");
							sfree(id);
							sfree(path);
							http_send_response(current_job->clientfd, "404", NULL,
							                   "File ID not found");
							disconnect_client(data->epfd, current_job);
							continue;
						}
						sfree(path);
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
						remove_dir(uuid_path);
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

int main(void) {
	if (create_dir(FILES_PATH) == -1) {
		return 1;
	}
	if (create_dir(CONFIG_PATH) == -1) {
		return 1;
	}
	if (create_file(PUBKEY_PATH) == -1) {
		return 1;
	}
	fise *data = (fise *)smalloc(sizeof(fise));
	if (create_http_server(data, "0.0.0.0", 80) == -1) {
		close_server(data);
		return 1;
	}
	int res = start_http_server(data);
	close_server(data);
	if (res == -1) {
		return 1;
	}
	return 0;
}
