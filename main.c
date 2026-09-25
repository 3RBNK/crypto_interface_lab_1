/// Три вида команд для консольной программы
/// main.exe keygen <[out] key_file>
/// main.exe encrypt <[in] ECB|CBC|CFB> <[in] key_file> <[in] input_file> <[out] iv_file> <[out] output_file>
/// main.exe decrypt <[in] ECB|CBC|CFB> <[in] key_file> <[in] input_file> <[out] output_file>


#include<stdlib.h>
#include "crypto.h"

#pragma  comment(lib, "bcrypt.lib")


int main(int argc, char* argv[]) {
	FunctionType fn_type = get_func_type(argv[1]);

	switch(fn_type) {
		case keygen: {
			KeygenArgs kg_args;
			init_keygen_args(&kg_args, argv[2]);

			NTSTATUS status = generate_key(&kg_args);

			break;
		}
		case encrypt: {
			EncryptArgs en_args;
			init_encrypt_args(&en_args, argv[2], argv[3], argv[4], argv[5], argv[6]);

			NTSTATUS status = encrypt_file(&en_args);

			break;
		}
		case decrypt: {
			DecryptArgs dc_args;
			init_decrypt_args(&dc_args, argv[2], argv[3], argv[4], argv[5], argv[6]);

			NTSTATUS status = decrypt_file(&dc_args);

			break;
		}
		case invalid: {
			printf("Unsupported command");
			break;
		}
	}


	return 0;
}