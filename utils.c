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

/**
 * @brief Считывает всё содержимое файла в память.
 *
 * @param path Путь к считываемому файлу.
 * @param buffer Указатель на переменную, в которую будет записан
 *               адрес выделенного буфера с содержимым файла.
 * @param size Указатель на переменную, в которую будет записан
 *             размер файла в байтах.
 *
 * @return 1 при успешном чтении файла, 0 при возникновении ошибки.
 */
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


/**
 * @brief Записывает содержимое буфера в файл.
 *
 * @param path Путь к файлу для записи.
 * @param buffer Указатель на буфер с записываемыми данными.
 * @param size Размер записываемых данных в байтах.
 *
 * @return 1 при успешной записи файла, 0 при возникновении ошибки.
 */
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
