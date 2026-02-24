// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#include "mem.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Deletes path directory recursively.
 * returns: 0 for success, -1 for error
 */
int remove_dir(const char *path) {
	DIR   *d        = opendir(path);
	size_t path_len = strlen(path);
	int    r        = -1;

	if (d) {
		struct dirent *p;
		r = 0;

		while (!r && (p = readdir(d))) {
			int    r2 = -1;
			char  *buf;
			size_t len;

			// Skip "." and ".."
			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) continue;

			len = path_len + strlen(p->d_name) + 2;
			buf = smalloc(len);

			struct stat statbuf;
			snprintf(buf, len, "%s/%s", path, p->d_name);

			if (!stat(buf, &statbuf)) {
				if (S_ISDIR(statbuf.st_mode))
					r2 = remove_dir(buf);
				else
					r2 = unlink(buf);
			}
			sfree(buf);
			r = r2;
		}
		closedir(d);
	}

	if (!r) r = rmdir(path);

	return r;
}

/*
 * Creates the passed dir directory if not already exists
 * returns: 0 for success, -1 for error
 */
int create_dir(const char *path) {
	struct stat st = {0};
	if (stat(path, &st) == -1) {
		if (errno == ENOENT) {
			char   tmp[PATH_MAX];
			char  *p = NULL;
			size_t len;

			snprintf(tmp, sizeof(tmp), "%s", path);
			len = strlen(tmp);
			if (tmp[len - 1] == '/') tmp[len - 1] = 0;
			for (p = tmp + 1; *p; p++)
				if (*p == '/') {
					*p = 0;
					if (mkdir(tmp, S_IRWXU) == -1 && errno != EEXIST) {
						printf("Error while creating directory %s: %s", path,
						       strerror(errno));
						return -1;
					}
					*p = '/';
				}
			if (mkdir(tmp, S_IRWXU) == -1 && errno != EEXIST) {
				printf("Error while creating directory %s: %s", path,
				       strerror(errno));
				return -1;
			}
			return 0;
		}
	}
	return 0;
}

/*
 * Creates an empty file at the passed path if not already exists
 * returns: 0 for success, -1 for error
 */
int create_file(const char *path) {
	struct stat st;
	if (stat(path, &st) == -1) {
		FILE *file = fopen(path, "w");
		if (file == NULL) {
			printf("Error while creating file %s: %s", path, strerror(errno));
			return -1;
		}
		fclose(file);
	}
	return 0;
}

/*
 * Opens the directory at path and opens the first file it finds.
 * This function is used for directories that contains only one file
 * returns: fd for success, -1 for error
 */
char *open_first(char *path, int *filefd) {
	DIR *dir = opendir(path);
	if (dir == NULL) {
		sfree(path);
		perror("Error while opening the requested api directory");
		return NULL;
	}

	struct dirent *entry;

	assert(*filefd == -1);

	char *file_name = NULL;
	while ((entry = readdir(dir)) != NULL) {
		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
			continue;
		}
		// Build full path
		char file_path[PATH_MAX];
		snprintf(file_path, sizeof(file_path), "%s/%s", path, entry->d_name);

		struct stat st;
		int         attributes = stat(file_path, &st);
		if (attributes == -1) {
			perror("Stat error");
			continue;
		}
		// Check if it's a regular file
		if (attributes == 0 && S_ISREG(st.st_mode)) {
			// Open the first regular file found
			*filefd   = open(file_path, O_RDONLY);
			file_name = strdup(entry->d_name);
			if (*filefd == -1) {
				perror("Failed to open file");
			}
			break;
		}
	}
	sfree(path);

	if (closedir(dir) == -1) {
		perror("Error while closing file directory");
	}
	return file_name;
}