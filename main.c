#include<stdlib.h>
#include "crypto.h"

int main(int argc, char* argv[]) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	if (argc < 2) {
		fprintf(stderr, "Usage: crypto keygen KEY | crypto encrypt|decrypt MODE KEY INPUT IV OUTPUT\n");
		return EXIT_FAILURE;
	}
	FunctionType fn_type = get_func_type(argv[1]);
	if ((fn_type == keygen && argc != 3) ||
		((fn_type == encrypt || fn_type == decrypt) && argc != 7)) {
		fprintf(stderr, "Usage: crypto keygen KEY | crypto encrypt|decrypt MODE KEY INPUT IV OUTPUT\n");
		return EXIT_FAILURE;
	}

	switch(fn_type) {
		case keygen: {
			KeygenArgs kg_args;
			init_keygen_args(&kg_args, argv[2]);

			status = generate_key(&kg_args);

			break;
		}
		case encrypt: {
			EncryptArgs en_args;
			init_encrypt_args(
				&en_args, 
				argv[2], 
				argv[3], 
				argv[4], 
				argv[5], 
				argv[6]
			);

			status = encrypt_file(&en_args);

			break;
		}
		case decrypt: {
			DecryptArgs dc_args;
			init_decrypt_args(
				&dc_args, 
				argv[2], 
				argv[3], 
				argv[4], 
				argv[5], 
				argv[6]
			);

			status = decrypt_file(&dc_args);
			break;
		}
		case invalid: {
			printf("Unsupported command");
			break;
		}
	}


	if (!NT_SUCCESS(status)) {
		fprintf(stderr, "Operation failed: NTSTATUS=0x%08lX\n", (unsigned long)(ULONG)status);
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
