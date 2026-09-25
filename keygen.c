#include "crypto.h"
#include <stdio.h>


void init_keygen_args(KeygenArgs* kg_args, const char* key_out) {
	kg_args->key_out = key_out;
}


NTSTATUS generate_key(const KeygenArgs* args) {
	BYTE key[AES_KEY_SIZE];

	NTSTATUS status = BCryptGenRandom(
		NULL,
		key,
		AES_KEY_SIZE,
		BCRYPT_USE_SYSTEM_PREFERRED_RNG
	);

	if (!NT_SUCCESS(status)) {
		printf("BCryptGenRandom failed: %x\n", status);
		return status;
	}

	if (!write_file(
		args->key_out,
		key,
		AES_KEY_SIZE
	)) {
		printf("Failed to write key to file\n");
		return STATUS_UNSUCCESSFUL;
	}

	return status;
}