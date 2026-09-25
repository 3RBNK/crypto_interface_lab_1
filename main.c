/// Три вида команд для консольной программы
/// main.exe keygen <key_file>
/// main.exe encrypt <ECB|CBC|CFB> <key_file> <input_file> [iv_file] <output_file>
/// main.exe decrypt <ECB|CBC|CFB> <key_file> <input_file> <output_file>


#include<windows.h>
#include<bcrypt.h>
#include<stdio.h>

#pragma  comment(lib, "bcrypt.lib")

#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define MAX_PATH_LEN 512


typedef struct {
	char* key_out;
} KeygenArgs;


typedef struct {
	char* mode;
	char* key_in;
	char* file_in;
	char* iv_out;
	char* file_out;
} EncryptArgs;


typedef struct {
	char* mode;
	char* key_in;
	char* file_in;
	char* iv_in;
	char* file_out;
} DecryptArgs;


typedef enum {
	keygen,
	encrypt,
	decrypt,
	invalid,
} FunctionType;


FunctionType get_func_type(const char* arg) {
	FunctionType func_type = invalid;

	if (strcmp(arg, "keygen") == 0) {
		func_type = keygen;
	} else if (strcmp(arg, "encrypt") == 0) {
		func_type = encrypt;
	} else if (strcmp(arg, "decrypt") == 0) {
		func_type = decrypt;
	}

	return func_type;
}


void init_keygen_args(KeygenArgs* kg_args, const char* key_out) {
	kg_args->key_out = key_out;
}

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


int main(int argc, char* argv[]) {
	FunctionType fn_type = get_func_type(argv[1]);

	switch(fn_type) {
		case keygen: {
			KeygenArgs kg_args;
			init_keygen_args(&kg_args, argv[2]);

			break;
		}
		case encrypt: {
			EncryptArgs en_args;
			init_encrypt_args(&en_args, argv[2], argv[3], argv[4], argv[5], argv[6]);

			break;
		}
		case decrypt: {
			DecryptArgs dc_args;
			init_decrypt_args(&dc_args, argv[2], argv[3], argv[4], argv[5], argv[6]);

			break;
		}
		case invalid: {
			printf("Unsupported command");
			break;
		}
	}


	return 0;
}