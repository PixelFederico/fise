// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#ifndef FISE_FILES
#define FISE_FILES

int   remove_dir(const char *path);
int   create_dir(const char *path);
int   create_file(const char *path);
char *open_first(const char *path, int *filefd);

#endif