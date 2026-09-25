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


NTSTATUS encrypt_file(const EncryptArgs* en_args) {
	return STATUS_UNSUCCESSFUL;
}


void free_encrypt_context(EncryptContext* ctx) {
	if (ctx->h_key) {
		BCryptDestroyKey(ctx->h_key);
	}

	if (ctx->h_alg) {
		BCryptCloseAlgorithmProvider(ctx->h_alg, 0);
	}

	free(ctx->key);
	(ctx->plain_text);
	(ctx->cipher_text);
	(ctx->key_object);
	(ctx->iv);
	(ctx->iv_copy);
}