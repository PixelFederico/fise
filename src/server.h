// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#ifndef FISE_SERVER
#define FISE_SERVER

#include <stdio.h>

enum CLIENT_STATUS {
	STATUS_IDLE,
	STATUS_SENDING_HEADERS,
	STATUS_DOWNLOADING,
	STATUS_UPLOADING,
	STATUS_DISCONNECTED,
	STATUS_WAITING_UPLOAD_ID
};

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
	long          last_status_change;
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

#endif