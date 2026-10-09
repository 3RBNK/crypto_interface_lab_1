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

	*buffer = (BYTE*)malloc(file_size > 0 ? (size_t)file_size : 1);

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

/*
 * The key must be configured for CFB with a 16-byte feedback size.
 * CNG requires complete CFB-128 blocks. Temporarily append zero bytes to
 * an incomplete message and discard the corresponding output bytes.
 * In CFB the extra bytes cannot affect the preceding output bytes.
 * This is not PKCS#7 padding: pass flags=0 and retain the original length.
 * This is a whole-message helper, not an incremental streaming interface.
 */
NTSTATUS crypt_cfb128(BCRYPT_KEY_HANDLE h_key, BYTE* input, DWORD input_size,
                     const BYTE* iv, BYTE* output, int decrypting) {
    DWORD remainder = input_size % AES_BLOCK_SIZE;
    DWORD padding_size = remainder ? AES_BLOCK_SIZE - remainder : 0;
    DWORD buffer_size;
    DWORD result_size = 0;
    BYTE working_iv[AES_BLOCK_SIZE];
    BYTE* padded_buffer = NULL;
    BYTE* crypt_input = input;
    BYTE* crypt_output = output;
    NTSTATUS status;

    if (input_size == 0) {
        return STATUS_SUCCESS;
    }
    /* Guard the 32-bit CNG length against overflow before rounding up. */
    if (input_size > (DWORD)-1 - padding_size) {
        return STATUS_UNSUCCESSFUL;
    }
    buffer_size = input_size + padding_size;
    if (padding_size != 0) {
        padded_buffer = (BYTE*)calloc(buffer_size, 1);
        if (padded_buffer == NULL) {
            return STATUS_UNSUCCESSFUL;
        }
        memcpy(padded_buffer, input, input_size);
        /* BCryptEncrypt/Decrypt support identical input and output buffers. */
        crypt_input = padded_buffer;
        crypt_output = padded_buffer;
    }

    memcpy(working_iv, iv, sizeof(working_iv));
    if (decrypting) {
        status = BCryptDecrypt(h_key, crypt_input, buffer_size, NULL,
            working_iv, sizeof(working_iv), crypt_output, buffer_size, &result_size, 0);
    }
    else {
        status = BCryptEncrypt(h_key, crypt_input, buffer_size, NULL,
            working_iv, sizeof(working_iv), crypt_output, buffer_size, &result_size, 0);
    }
    if (NT_SUCCESS(status) && result_size != buffer_size) {
        status = STATUS_UNSUCCESSFUL;
    }
    if (padded_buffer != NULL) {
        if (NT_SUCCESS(status)) {
            memcpy(output, padded_buffer, input_size);
        }
        SecureZeroMemory(padded_buffer, buffer_size);
        free(padded_buffer);
    }
    return status;
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
