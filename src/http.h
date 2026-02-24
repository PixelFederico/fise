// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#ifndef FISE_HTTP
#define FISE_HTTP

#include "string.h"

struct s_header_node {
	char *key;
	char *value;
	char *keys; // Pointer to all keys contained in the current instance and
	            // next (recursive). This pointer is only contained at the
	            // instance where it begins the first use of the same
	struct s_header_node *next;
};

typedef struct s_header_node header_node;

header_node *create_headers(const char *labels, ...);
int          http_send_response(const int clientfd, const char *code,
                                header_node *headers, const char *message);
char        *find_http_header_value(char *request, const size_t request_len,
                                    const char *header);

#endif