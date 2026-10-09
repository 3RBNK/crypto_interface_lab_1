#include "crypto.h"
#include <stdio.h>


void init_encrypt_args(EncryptArgs* en_args,
	                   const char* mode,
	                   const char* key_in,
	                   const char* file_in,
	                   const char* iv_out,
	                   const char* file_out) {
	en_args->mode = mode;
	en_args->key_in = key_in;
	en_args->file_in = file_in;
	en_args->iv_out = iv_out;
	en_args->file_out = file_out;
}


/**
 * @brief Шифрует содержимое входного файла с использованием алгоритма AES.
 *
 * Выполняет чтение ключа и исходного файла, настраивает выбранный режим
 * шифрования, создаёт объект симметричного ключа и выполняет шифрование
 * данных.
 *
 * Для режимов CBC и CFB дополнительно генерируется и сохраняется
 * инициализирующий вектор.
 *
 * @param args Указатель на структуру EncryptArgs, содержащую режим
 *             шифрования и пути к файлу ключа, входному файлу,
 *             файлу IV и выходному зашифрованному файлу.
 *
 * @return Код NTSTATUS. При успешном выполнении возвращается STATUS_SUCCESS,
 *         при возникновении ошибки — соответствующий код ошибки.
 */
NTSTATUS encrypt_file(const EncryptArgs* args) {
    EncryptContext ctx = { 0 };

    NTSTATUS status = STATUS_UNSUCCESSFUL;

    DWORD key_size = 0;
    DWORD plain_text_size = 0;
    DWORD cipher_text_size = 0;
    DWORD result_size = 0;

    DWORD key_object_size = 0;
    DWORD block_size = 0;
    DWORD cb_data = 0;

    LPCWSTR chain_mode = NULL;

    int uses_iv = 0;
    int is_cfb = 0;

    BYTE* padded_plain = NULL;
    BYTE* encrypt_input = NULL;

    DWORD encrypt_input_size = 0;
    DWORD original_plain_size = 0;

    ULONG encrypt_flags = BCRYPT_BLOCK_PADDING;

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

        /*
         * Для CFB padding не используем.
         */
        encrypt_flags = 0;
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

    if (
        key_size != 16 &&
        key_size != 24 &&
        key_size != 32
        ) {
        free_encrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Чтение исходного файла.
     */
    if (!read_file(
        args->file_in,
        &ctx.plain_text,
        &plain_text_size
    )) {
        free_encrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    original_plain_size = plain_text_size;

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
        free_encrypt_context(&ctx);
        return status;
    }

    /*
     * Устанавливаем режим ECB / CBC / CFB.
     */
    status = BCryptSetProperty(
        ctx.h_alg,
        BCRYPT_CHAINING_MODE,
        (PBYTE)chain_mode,
        (ULONG)((wcslen(chain_mode) + 1) * sizeof(WCHAR)),
        0
    );

    if (!NT_SUCCESS(status)) {
        free_encrypt_context(&ctx);
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
        free_encrypt_context(&ctx);
        return status;
    }

    ctx.key_object = (BYTE*)malloc(key_object_size);

    if (ctx.key_object == NULL) {
        free_encrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Получаем размер блока AES.
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
        free_encrypt_context(&ctx);
        return status;
    }

    /*
     * CBC и CFB используют IV.
     */
    if (uses_iv) {
        ctx.iv = (BYTE*)malloc(block_size);

        if (ctx.iv == NULL) {
            free_encrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }

        ctx.iv_copy = (BYTE*)malloc(block_size);

        if (ctx.iv_copy == NULL) {
            free_encrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }

        /*
         * Для обычного шифрования генерируем случайный IV.
         */
        status = BCryptGenRandom(
            NULL,
            ctx.iv,
            block_size,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        if (!NT_SUCCESS(status)) {
            free_encrypt_context(&ctx);
            return status;
        }
    }

    /*
     * Создаём объект симметричного ключа.
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
        free_encrypt_context(&ctx);
        return status;
    }

    /*
     * CFB-128:
     * размер feedback = размер блока AES = 16 байт.
     */
    if (is_cfb) {
        DWORD message_block_length = block_size;

        status = BCryptSetProperty(
            ctx.h_key,
            BCRYPT_MESSAGE_BLOCK_LENGTH,
            (PUCHAR)&message_block_length,
            sizeof(DWORD),
            0
        );

        if (!NT_SUCCESS(status)) {
            free_encrypt_context(&ctx);
            return status;
        }
    }

    /*
     * По умолчанию шифруем исходный plaintext.
     */
    encrypt_input = ctx.plain_text;
    encrypt_input_size = plain_text_size;

    /*
     * BCryptEncrypt без BCRYPT_BLOCK_PADDING
     * требует размер входа, кратный размеру блока.
     *
     * Поэтому для CFB-128 временно дополняем
     * последний неполный блок нулями.
     *
     * После шифрования лишние байты ciphertext
     * просто не сохраняются.
     */
    if (
        is_cfb &&
        plain_text_size % block_size != 0
        ) {
        DWORD padded_size =
            ((plain_text_size + block_size - 1) /
                block_size) *
            block_size;

        padded_plain = (BYTE*)calloc(
            padded_size,
            1
        );

        if (padded_plain == NULL) {
            free_encrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }

        memcpy(
            padded_plain,
            ctx.plain_text,
            plain_text_size
        );

        encrypt_input = padded_plain;
        encrypt_input_size = padded_size;
    }

    /*
     * Перед первым BCryptEncrypt восстанавливаем IV.
     */
    if (uses_iv) {
        memcpy(
            ctx.iv_copy,
            ctx.iv,
            block_size
        );
    }

    /*
     * Первый вызов:
     * узнаём размер выходного буфера.
     */
    status = BCryptEncrypt(
        ctx.h_key,
        encrypt_input,
        encrypt_input_size,
        NULL,
        uses_iv ? ctx.iv_copy : NULL,
        uses_iv ? block_size : 0,
        NULL,
        0,
        &cipher_text_size,
        encrypt_flags
    );

    if (!NT_SUCCESS(status)) {
        if (padded_plain != NULL) {
            free(padded_plain);
        }

        free_encrypt_context(&ctx);
        return status;
    }

    ctx.cipher_text = (BYTE*)malloc(
        cipher_text_size
    );

    if (ctx.cipher_text == NULL) {
        if (padded_plain != NULL) {
            free(padded_plain);
        }

        free_encrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    /*
     * Первый BCryptEncrypt мог изменить IV,
     * поэтому снова восстанавливаем его.
     */
    if (uses_iv) {
        memcpy(
            ctx.iv_copy,
            ctx.iv,
            block_size
        );
    }

    /*
     * Фактическое шифрование.
     */
    status = BCryptEncrypt(
        ctx.h_key,
        encrypt_input,
        encrypt_input_size,
        NULL,
        uses_iv ? ctx.iv_copy : NULL,
        uses_iv ? block_size : 0,
        ctx.cipher_text,
        cipher_text_size,
        &result_size,
        encrypt_flags
    );

    if (padded_plain != NULL) {
        free(padded_plain);
        padded_plain = NULL;
    }

    if (!NT_SUCCESS(status)) {
        free_encrypt_context(&ctx);
        return status;
    }

    /*
     * Для CBC и CFB сохраняем IV.
     */
    if (uses_iv) {
        if (!write_file(
            args->iv_out,
            ctx.iv,
            block_size
        )) {
            free_encrypt_context(&ctx);
            return STATUS_UNSUCCESSFUL;
        }
    }

    /*
     * ECB / CBC:
     * сохраняем весь result_size,
     * включая padding.
     *
     * CFB:
     * если вход временно дополнялся до полного блока,
     * сохраняем только столько байт ciphertext,
     * сколько было байт исходного plaintext.
     */
    DWORD write_size;

    if (is_cfb) {
        write_size = original_plain_size;
    }
    else {
        write_size = result_size;
    }

    if (!write_file(
        args->file_out,
        ctx.cipher_text,
        write_size
    )) {
        free_encrypt_context(&ctx);
        return STATUS_UNSUCCESSFUL;
    }

    printf("Encryption successful\n");

    free_encrypt_context(&ctx);

    return STATUS_SUCCESS;
}


void free_encrypt_context(EncryptContext* ctx) {
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