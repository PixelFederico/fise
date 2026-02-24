// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#ifndef FISE_SOCKET
#define FISE_SOCKET

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>

int    create_address(struct sockaddr_in *sockaddr, const char *addr,
                      const uint16_t port);
int    create_socket(const char *addr, const uint16_t port,
                     struct sockaddr_in *sockaddr, int *sockfd);
int    socket_start_listener(const int sockfd, int *epfd);
size_t socket_send(const int clientfd, const char *message,
                   const size_t message_len);

#endif