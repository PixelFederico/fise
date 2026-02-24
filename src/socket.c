// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#include "socket.h"
#include "mem.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#define LISTEN_BACKLOG 4096

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
	    (struct epoll_event *)smalloc(sizeof(struct epoll_event));
	socketfd_event->events  = EPOLLIN;
	socketfd_event->data.fd = sockfd;

	if (epoll_ctl(*epfd, EPOLL_CTL_ADD, sockfd, socketfd_event) == -1) {
		sfree(socketfd_event);
		perror("Error while adding the server socket to events listener");
		return -1;
	}
	sfree(socketfd_event);
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