// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#include "jwt.h"
#include "http.h"
#include "mem.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>

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
	char *base64_str = smalloc(input_len + 1);

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
		base64_str = srealloc(base64_str, input_len + padding + 1);
		for (size_t i = 0; i < padding; i++) {
			base64_str[input_len + i] = '=';
		}
		base64_str[input_len + padding] = '\0';
	}

	BIO           *bio, *b64;
	size_t         decode_len = strlen(base64_str);
	unsigned char *buffer     = smalloc(decode_len);

	bio                       = BIO_new_mem_buf(base64_str, -1);
	b64                       = BIO_new(BIO_f_base64());
	bio                       = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	*output_len = BIO_read(bio, buffer, decode_len);

	BIO_free_all(bio);
	sfree(base64_str);

	return buffer;
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
		sfree(authorization);
		return 0;
	}
	token = strtok(NULL, " ");
	if (token == NULL) {
		sfree(authorization);
		return 0;
	}
	char *header_end = strchr(token, '.');
	if (header_end == NULL) {
		sfree(authorization);
		return 0;
	}
	char *payload_end = strchr(header_end + 1, '.');
	if (payload_end == NULL) {
		sfree(authorization);
		return 0;
	}
	size_t sig_start = payload_end - token + 1;

	size_t         sig_len;
	unsigned char *signature =
	    base64url_decode(token + sig_start, strlen(token + sig_start), &sig_len);

	if (signature == NULL) {
		sfree(authorization);
		return 0;
	}
	size_t         pubkey_len;
	unsigned char *pubkey_raw =
	    base64url_decode(pubkey, strlen(pubkey), &pubkey_len);
	if (pubkey_raw == NULL) {
		sfree(signature);
		sfree(authorization);
		return 0;
	}
	EVP_PKEY *pkey  = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL,
	                                              pubkey_raw, pubkey_len);

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (ctx == NULL || !EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey)) {
		printf("Error in POST request digest verify init\n");
		if (ctx) EVP_MD_CTX_free(ctx);
		EVP_PKEY_free(pkey);
		sfree(authorization);
		sfree(signature);
		sfree(pubkey_raw);
		return 0;
	}

	size_t message_len = payload_end - token;
	int    result      = EVP_DigestVerify(ctx, signature, sig_len,
	                                      (unsigned char *)token, message_len);

	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	sfree(signature);
	sfree(pubkey_raw);

	if (result != 1) {
		if (result == 0) {
			printf("POST request received with invalid jwt "
			       "signature\n");
		} else {
			printf("POST request received with invalid jwt "
			       "signature: Error %lo\n",
			       ERR_get_error());
		}
		sfree(authorization);
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
		sfree(authorization);
		return 0;
	}

	// JWT parsing
	char *payload_json = smalloc(decoded_payload_len + 1);
	memcpy(payload_json, decoded_payload, decoded_payload_len);
	payload_json[decoded_payload_len] = '\0';
	sfree(decoded_payload);

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

	sfree(payload_json);
	sfree(authorization);

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