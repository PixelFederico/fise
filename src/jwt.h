// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#ifndef FISE_JWT
#define FISE_JWT

#include <string.h>

enum REQUIRE_AUTH_LEVEL { REQUEST_USER, REQUEST_ADMIN };

unsigned char *base64url_decode(const char *input, const size_t input_len,
                                size_t *output_len);
int is_jwt_valid(char *headers, const int headers_len, const int request_mode,
                 const char *pubkey);

#endif