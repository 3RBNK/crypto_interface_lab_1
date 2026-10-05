#include "crypto.h"
#include <stdio.h>


void init_decrypt_args(DecryptArgs* dc_args,
	                   const char* mode,
	                   const char* key_in,
	                   const char* file_in,
	                   const char* iv_in,
	                   const char* file_out) {
	dc_args->mode = mode;
	dc_args->key_in = key_in;
	dc_args->file_in = file_in;
	dc_args->iv_in = iv_in;
	dc_args->file_out = file_out;
}


static NTSTATUS decrypt_cfb128(
	DecryptContext* ctx,
	DWORD key_size,
	DWORD cipher_text_size,
	DWORD block_size,
	DWORD key_object_size
) {
	if (block_size != 16) {
		return STATUS_UNSUCCESSFUL;
	}

	NTSTATUS status;
	LPCWSTR ecb_mode = BCRYPT_CHAIN_MODE_ECB;

	status = BCryptSetProperty(
		ctx->h_alg,
		BCRYPT_CHAINING_MODE,
		(PBYTE)ecb_mode,
		(ULONG)(wcslen(ecb_mode) + 1) * sizeof(WCHAR),
		0
	);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	status = BCryptGenerateSymmetricKey(
		ctx->h_alg,
		&ctx->h_key,
		ctx->key_object,
		key_object_size,
		ctx->key,
		key_size,
		0
	);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	ctx->plain_text = (BYTE*)malloc(cipher_text_size);

	if (ctx->plain_text == NULL) {
		return STATUS_UNSUCCESSFUL;
	}

	BYTE feedback[16];
	BYTE gamma[16];

	memcpy(feedback, ctx->iv, block_size);

	DWORD offset = 0;

	while (offset < cipher_text_size) {
		DWORD gamma_size = 0;

		status = BCryptEncrypt(
			ctx->h_key,
			feedback,
			block_size,
			NULL,
			NULL,
			0,
			gamma,
			block_size,
			&gamma_size,
			0
		);

		if (!NT_SUCCESS(status)) {
			return status;
		}

		DWORD chunk_size = cipher_text_size - offset;

		if (chunk_size > block_size) {
			chunk_size = block_size;
		}

		for (DWORD i = 0; i < chunk_size; i++) {
			ctx->plain_text[offset + i] =
				ctx->cipher_text[offset + i] ^ gamma[i];
		}

		if (chunk_size == block_size) {
			memcpy(
				feedback,
				ctx->cipher_text + offset,
				block_size
			);
		}

		offset += chunk_size;
	}

	return STATUS_SUCCESS;
}

/**
 * @brief Расшифровывает содержимое зашифрованного файла с использованием AES.
 *
 * Выполняет чтение ключа, зашифрованного файла и, при необходимости,
 * инициализирующего вектора, настраивает выбранный режим шифрования
 * и выполняет расшифрование данных.
 *
 * @param args Указатель на структуру DecryptArgs, содержащую режим
 *             шифрования и пути к файлу ключа, зашифрованному файлу,
 *             файлу IV и выходному расшифрованному файлу.
 *
 * @return Код NTSTATUS. При успешном выполнении возвращается STATUS_SUCCESS,
 *         при возникновении ошибки — соответствующий код ошибки.
 */
NTSTATUS decrypt_file(const DecryptArgs* args) {
	DecryptContext ctx = { 0 };

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	DWORD key_size = 0;
	DWORD cipher_text_size = 0;
	DWORD plain_text_size = 0;
	DWORD result_size = 0;
	DWORD key_object_size = 0;
	DWORD block_size = 0;
	DWORD cb_data = 0;

	int uses_iv = 0;
	LPCWSTR chain_mode = NULL;

	if (strcmp(args->mode, "CBC") == 0) {
		chain_mode = BCRYPT_CHAIN_MODE_CBC;
		uses_iv = 1;
	}
	else if (strcmp(args->mode, "ECB") == 0) {
		chain_mode = BCRYPT_CHAIN_MODE_ECB;
		uses_iv = 0;
	}
	else if (strcmp(args->mode, "CFB") == 0) {
		chain_mode = BCRYPT_CHAIN_MODE_CFB;
		uses_iv = 1;
	}
	else {
		return STATUS_UNSUCCESSFUL;
	}

	if (!read_file(args->key_in, &ctx.key, &key_size)) {
		return STATUS_UNSUCCESSFUL;
	}

	if (key_size != 16 && key_size != 24 && key_size != 32) {
		free_decrypt_context(&ctx);
		return STATUS_UNSUCCESSFUL;
	}


	if (!read_file(args->file_in, &ctx.cipher_text, &cipher_text_size)) {
		free_decrypt_context(&ctx);
		return STATUS_UNSUCCESSFUL;
	}


	status = BCryptOpenAlgorithmProvider(
		&ctx.h_alg,
		BCRYPT_AES_ALGORITHM,
		NULL,
		0
	);

	if (!NT_SUCCESS(status)) {
		free_decrypt_context(&ctx);
		return status;
	}


	status = BCryptSetProperty(
		ctx.h_alg,
		BCRYPT_CHAINING_MODE,
		(PBYTE)chain_mode,
		(ULONG)(wcslen(chain_mode) + 1) * sizeof(WCHAR),
		0
	);

	if (!NT_SUCCESS(status)) {
		free_decrypt_context(&ctx);
		return status;
	}

	printf(
		"Set CFB block length status: 0x%08X\n",
		(unsigned int)status
	);


	status = BCryptGetProperty(
		ctx.h_alg,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&key_object_size,
		sizeof(DWORD),
		&cb_data,
		0);

	if (!NT_SUCCESS(status)) {
		free_decrypt_context(&ctx);
		return status;
	}

	printf(
		"Decrypt size status: 0x%08X, cipher=%lu, plain=%lu\n",
		(unsigned int)status,
		cipher_text_size,
		plain_text_size
	);

	ctx.key_object = (BYTE*)malloc(key_object_size);
	if (ctx.key_object == NULL) {
		free_decrypt_context(&ctx);
		return STATUS_UNSUCCESSFUL;
	}


	status = BCryptGetProperty(
		ctx.h_alg,
		BCRYPT_BLOCK_LENGTH,
		(PUCHAR)&block_size,
		sizeof(DWORD),
		&cb_data,
		0);

	if (!NT_SUCCESS(status)) {
		free_decrypt_context(&ctx);
		return status;
	}

	printf(
		"Decrypt data status: 0x%08X, result=%lu\n",
		(unsigned int)status,
		result_size
	);


	if (uses_iv) {
		DWORD iv_size = 0;

		if (!read_file(args->iv_in, &ctx.iv, &iv_size)) {
			free_decrypt_context(&ctx);
			return STATUS_UNSUCCESSFUL;
		}

		if (iv_size != block_size) {
			printf("Invalid IV size\n");
			free_decrypt_context(&ctx);
			return STATUS_UNSUCCESSFUL;
		}

		ctx.iv_copy = (BYTE*)malloc(block_size);

		if (ctx.iv_copy == NULL) {
			free_decrypt_context(&ctx);
			return STATUS_UNSUCCESSFUL;
		}
	}

	if (strcmp(args->mode, "CFB") == 0) {
		status = decrypt_cfb128(
			&ctx,
			key_size,
			cipher_text_size,
			block_size,
			key_object_size
		);

		if (!NT_SUCCESS(status)) {
			free_decrypt_context(&ctx);
			return status;
		}

		if (!write_file(
			args->file_out,
			ctx.plain_text,
			cipher_text_size
		)) {
			free_decrypt_context(&ctx);
			return STATUS_UNSUCCESSFUL;
		}

		printf("Decryption successful\n");

		free_decrypt_context(&ctx);
		return STATUS_SUCCESS;
	}

	status = BCryptGenerateSymmetricKey(
		ctx.h_alg,
		&ctx.h_key,
		ctx.key_object,
		key_object_size,
		ctx.key,
		key_size,
		0
	);

	if (!NT_SUCCESS(status)) {
		free_decrypt_context(&ctx);
		return status;
	}

	status = BCryptSetProperty(
		ctx.h_key,
		BCRYPT_MESSAGE_BLOCK_LENGTH,
		(PUCHAR)&block_size,
		sizeof(DWORD),
		0
	);

	if (!NT_SUCCESS(status)) {
		free_decrypt_context(&ctx);
		return status;
	}

	if (uses_iv) {
		memcpy(ctx.iv_copy, ctx.iv, block_size);
	}

	status = BCryptDecrypt(
		ctx.h_key,
		ctx.cipher_text,
		cipher_text_size,
		NULL,
		uses_iv ? ctx.iv_copy : NULL,
		uses_iv ? block_size : 0,
		NULL,
		0,
		&plain_text_size,
		BCRYPT_BLOCK_PADDING
	);

	if (!NT_SUCCESS(status)) {
		free_decrypt_context(&ctx);
		return status;
	}


	ctx.plain_text = (BYTE*)malloc(plain_text_size);
	if (ctx.plain_text == NULL) {
		free_decrypt_context(&ctx);
		return STATUS_UNSUCCESSFUL;
	}


	if (uses_iv) {
		memcpy(ctx.iv_copy, ctx.iv, block_size);
	}


	status = BCryptDecrypt(
		ctx.h_key,
		ctx.cipher_text,
		cipher_text_size,
		NULL,
		uses_iv ? ctx.iv_copy : NULL,
		uses_iv ? block_size : 0,
		ctx.plain_text,
		plain_text_size,
		&result_size,
		BCRYPT_BLOCK_PADDING
	);

	if (!NT_SUCCESS(status)) {
		free_decrypt_context(&ctx);
		return status;
	}


	if (!write_file(args->file_out, ctx.plain_text, result_size)) {
		free_decrypt_context(&ctx);
		return STATUS_UNSUCCESSFUL;
	}

	printf("Decryption successful\n");


	free_decrypt_context(&ctx);

	return status;
}


void free_decrypt_context(DecryptContext* ctx) {
	if (ctx->h_key) {
		BCryptDestroyKey(ctx->h_key);
	}
	
	if (ctx->h_alg) {
		BCryptCloseAlgorithmProvider(ctx->h_alg, 0);
	}

	
	free(ctx->key);
	free(ctx->plain_text);
	free(ctx->cipher_text);
	free(ctx->key_object);
	free(ctx->iv);
	free(ctx->iv_copy);
}