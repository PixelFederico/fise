// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#ifndef FISE_MEM
#define FISE_MEM

#include <stdio.h>

void *smalloc(size_t size);
void *srealloc(void *ptr, size_t size);
void  sfree(void *ptr);

#endif