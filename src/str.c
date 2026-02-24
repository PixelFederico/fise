// Copyright (c) Federico Valeri
// Licensed under the MIT License. See LICENSE file in the project root.

#include "str.h"
#include "mem.h"
#include <stdarg.h>
#include <stdio.h>

/* Builds a new string by inserting the (...) values according to format
 * (format working like printf)
 * returns: The pointer of the string. Remember to free after use
 */
char *new_str(char *format, ...) {
	va_list arg, arg2;
	va_start(arg, format);
	va_copy(arg2, arg);
	int len = vsnprintf(NULL, 0, format, arg);
	va_end(arg);
	if (len <= 0) {
		va_end(arg2);
		return NULL;
	}
	char *str = smalloc(len + 1);

	if (vsprintf(str, format, arg2) < 0) {
		sfree(str);
		perror("vsprintf");
		va_end(arg2);
		return NULL;
	}
	va_end(arg2);
	return str;
}