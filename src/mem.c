// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#include "mem.h"

#include <stdio.h>
#include <stdlib.h>

/*
 * Wrapper of the malloc function, if there is an error the program stops
 */
void *smalloc(size_t size) {
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
void *srealloc(void *ptr, size_t size) {
	void *new_ptr = realloc(ptr, size);
	if (new_ptr == NULL) {
		perror("Realloc failed");
		exit(EXIT_FAILURE);
	}
	return new_ptr;
}

/*
 * Wrapper of the free function, currently it only needs for better
 * maintainability
 */
void sfree(void *ptr) { free(ptr); }