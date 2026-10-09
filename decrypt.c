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

    LPCWSTR chain_mode = NULL;

    int uses_iv = 0;
    int is_cfb = 0;

    /*
     * Выбор режима.
     */
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
        is_cfb = 1;
    }
    else {
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Чтение ключа.
     */
    if (!read_file(
        args->key_in,
        &ctx.key,
        &key_size
    )) {
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * AES поддерживает ключи:
     * 128 бит = 16 байт
     * 192 бита = 24 байта
     * 256 бит = 32 байта
     */
    if (
        key_size != 16 &&
        key_size != 24 &&
        key_size != 32
        ) {
        free_decrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Чтение шифротекста.
     */
    if (!read_file(
        args->file_in,
        &ctx.cipher_text,
        &cipher_text_size
    )) {
        free_decrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Открываем AES.
     */
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

    /*
     * Устанавливаем ECB / CBC / CFB.
     */
    status = BCryptSetProperty(
        ctx.h_alg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)chain_mode,
        (ULONG)((wcslen(chain_mode) + 1) * sizeof(WCHAR)),
        0
    );

    if (!NT_SUCCESS(status)) {
        free_decrypt_context(&ctx);
        return status;
    }

    /*
     * Получаем размер внутреннего объекта ключа.
     */
    status = BCryptGetProperty(
        ctx.h_alg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&key_object_size,
        sizeof(DWORD),
        &cb_data,
        0
    );

    if (!NT_SUCCESS(status)) {
        free_decrypt_context(&ctx);
        return status;
    }

    ctx.key_object = (BYTE*)malloc(key_object_size);

    if (ctx.key_object == NULL) {
        free_decrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Получаем размер блока AES.
     * Для AES это 16 байт.
     */
    status = BCryptGetProperty(
        ctx.h_alg,
        BCRYPT_BLOCK_LENGTH,
        (PUCHAR)&block_size,
        sizeof(DWORD),
        &cb_data,
        0
    );

    if (!NT_SUCCESS(status)) {
        free_decrypt_context(&ctx);
        return status;
    }

    /*
     * Читаем IV для CBC и CFB.
     */
    if (uses_iv) {
        DWORD iv_size = 0;

        if (!read_file(
            args->iv_in,
            &ctx.iv,
            &iv_size
        )) {
            free_decrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }

        if (iv_size != block_size) {
            printf("Invalid IV size\n");

            free_decrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }

        /*
         * BCryptDecrypt может менять IV,
         * поэтому работаем с его копией.
         */
        ctx.iv_copy = (BYTE*)malloc(block_size);

        if (ctx.iv_copy == NULL) {
            free_decrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }
    }

    /*
     * Создаём CNG-объект ключа из считанных байтов.
     */
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

    if (is_cfb) {
        /* CFB means CFB-128, not CNG's default CFB-8. */
        DWORD message_block_length = AES_BLOCK_SIZE;
        if (block_size != AES_BLOCK_SIZE) {
            free_decrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }
        status = BCryptSetProperty(ctx.h_key, BCRYPT_MESSAGE_BLOCK_LENGTH,
            (PUCHAR)&message_block_length, sizeof(message_block_length), 0);
        if (!NT_SUCCESS(status)) {
            free_decrypt_context(&ctx);
            return status;
        }

        ctx.plain_text = (BYTE*)malloc(cipher_text_size ? cipher_text_size : 1);
        if (ctx.plain_text == NULL) {
            free_decrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }
        status = crypt_cfb128(ctx.h_key, ctx.cipher_text, cipher_text_size,
            ctx.iv, ctx.plain_text, 1);
        result_size = cipher_text_size;
    }
    else {
        if (uses_iv) {
            memcpy(ctx.iv_copy, ctx.iv, block_size);
        }
        status = BCryptDecrypt(ctx.h_key, ctx.cipher_text, cipher_text_size,
            NULL, uses_iv ? ctx.iv_copy : NULL, uses_iv ? block_size : 0,
            NULL, 0, &plain_text_size, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) {
            free_decrypt_context(&ctx);
            return status;
        }

        ctx.plain_text = (BYTE*)malloc(plain_text_size ? plain_text_size : 1);
        if (ctx.plain_text == NULL) {
            free_decrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }
        if (uses_iv) {
            memcpy(ctx.iv_copy, ctx.iv, block_size);
        }
        status = BCryptDecrypt(ctx.h_key, ctx.cipher_text, cipher_text_size,
            NULL, uses_iv ? ctx.iv_copy : NULL, uses_iv ? block_size : 0,
            ctx.plain_text, plain_text_size, &result_size, BCRYPT_BLOCK_PADDING);
    }

    if (!NT_SUCCESS(status)) {
        free_decrypt_context(&ctx);
        return status;
    }

    if (!write_file(
        args->file_out,
        ctx.plain_text,
        result_size
    )) {
        free_decrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    printf("Decryption successful\n");

    free_decrypt_context(&ctx);

    return STATUS_SUCCESS;
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
