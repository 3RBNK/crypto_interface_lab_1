#include "crypto.h"
#include <stdlib.h>


FunctionType get_func_type(const char* arg) {
	FunctionType func_type = invalid;

	if (strcmp(arg, "keygen") == 0) {
		func_type = keygen;
	}
	else if (strcmp(arg, "encrypt") == 0) {
		func_type = encrypt;
	}
	else if (strcmp(arg, "decrypt") == 0) {
		func_type = decrypt;
	}

	return func_type;
}


int read_file(const char* path, BYTE** buffer, DWORD* size) {
	FILE* file = NULL;

	if (fopen_s(&file, path, "rb") != 0 || file == NULL) {
		printf("Can't open file for reading: %s\n", path);
		return 0;
	}

	fseek(file, 0, SEEK_END);

	long file_size = ftell(file);

	if (file_size < 0) {
		fclose(file);
		return 0;
	}

	rewind(file);

	*buffer = (BYTE*)malloc(file_size);

	if (*buffer == NULL) {
		fclose(file);
		return 0;
	}

	size_t bytes_read = fread(
		*buffer,
		1,
		file_size,
		file
	);

	fclose(file);

	if (bytes_read != (size_t)file_size) {
		free(*buffer);
		*buffer = NULL;
		return 0;
	}

	*size = (DWORD)file_size;

	return 1;
}


int write_file(const char* path, BYTE* buffer, DWORD size) {
	FILE* file = NULL;

	if (fopen_s(&file, path, "wb") != 0 || file == NULL) {
		printf("Cannot open file for writing: %s\n", path);
		return 0;
	}

	size_t bytes_written = fwrite(
		buffer,
		1,
		size,
		file
	);

	fclose(file);

	if (bytes_written != size) {
		return 0;
	}

	return 1;
}
