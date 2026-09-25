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


NTSTATUS decrypt_file(const DecryptArgs* dc_args) {
	return STATUS_UNSUCCESSFUL;
}