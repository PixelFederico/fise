// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#include "http.h"
#include "mem.h"
#include "socket.h"

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ALLOW_METHODS "GET, POST, OPTIONS, DELETE"
#define ALLOW_ORIGIN "*"
#define ALLOW_HEADERS "*"

/*
 * Frees headers linked list recursively, also frees keys
 */
void free_headers(header_node *headers) {
	if (headers->keys) sfree(headers->keys);
	if (headers->next != NULL) free_headers(headers->next);
	sfree(headers);
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
		header_node *current_header = smalloc(sizeof(header_node));

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
			response_body = smalloc(body_len + 1);
			if (sprintf(response_body, "{\"success\":\"%s\"}", message) < 0) {
				sfree(response_body);
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
			response_body = smalloc(body_len + 1);
			if (sprintf(response_body, "{\"error\":\"%s\"}", message) < 0) {
				sfree(response_body);
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
		if (message) sfree(response_body);
		free_headers(headers);
		return -1;
	}
	char *response = smalloc(len + 1);
	if (sprintf(response, "HTTP/1.1 %s\r\n", code) < 0) {
		sfree(response);
		if (message) sfree(response_body);
		free_headers(headers);
		return -1;
	}
	socket_send(clientfd, response, len);
	sfree(response);
	{
		// Convert each entry of the headers linked list and send on the socket
		header_node *current_header = headers;
		do {
			int header_len = snprintf(NULL, 0, "%s:%s\r\n", current_header->key,
			                          current_header->value);
			if (header_len < 0) {
				if (message) sfree(response_body);
				free_headers(headers);
				return -1;
			}

			char *header = smalloc(header_len + 1);
			if (sprintf(header, "%s:%s\r\n", current_header->key,
			            current_header->value) < 0) {
				sfree(header);
				if (message) sfree(response_body);
				free_headers(headers);
				return -1;
			}
			socket_send(clientfd, header, header_len);
			sfree(header);
			current_header = current_header->next;
		} while (current_header);
	}
	if (message) {
		int header_len = snprintf(NULL, 0, "Content-Length:%lu\r\n\r\n",
		                          strlen(response_body));
		if (header_len < 0) {
			sfree(response_body);
			free_headers(headers);
			return -1;
		}

		char *header = smalloc(header_len + 1);
		if (sprintf(header, "Content-Length:%lu\r\n\r\n", strlen(response_body)) <
		    0) {
			sfree(header);
			sfree(response_body);
			free_headers(headers);
			return -1;
		}
		socket_send(clientfd, header, header_len);
		sfree(header);
		socket_send(clientfd, response_body, strlen(response_body));
		sfree(response_body);
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
	char  *value     = smalloc(value_len + 1);
	memcpy(value, value_start, value_len);
	value[value_len] = '\0';

	return value;
}