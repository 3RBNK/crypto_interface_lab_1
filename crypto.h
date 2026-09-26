#ifndef CRYPTO_H
#define CRYPTO_H


#include <stdio.h>
#include <windows.h>
#include <bcrypt.h>

#define AES_KEY_SIZE 16
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)


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
	BCRYPT_ALG_HANDLE h_alg;
	BCRYPT_KEY_HANDLE h_key;

	BYTE* key;
	BYTE* plain_text;
	BYTE* cipher_text;
	BYTE* key_object;
	BYTE* iv;
	BYTE* iv_copy;
} EncryptContext;


typedef struct {
	char* mode;
	char* key_in;
	char* file_in;
	char* iv_in;
	char* file_out;
} DecryptArgs;

typedef struct {
	BCRYPT_ALG_HANDLE h_alg;
	BCRYPT_KEY_HANDLE h_key;

	BYTE* key;
	BYTE* plain_text;
	BYTE* cipher_text;
	BYTE* key_object;
	BYTE* iv;
	BYTE* iv_copy;
} DecryptContext;


typedef enum {
	keygen,
	encrypt,
	decrypt,
	invalid,
} FunctionType;

FunctionType get_func_type(const char* arg);


void init_keygen_args(KeygenArgs* kg_args, const char* key_out);
void init_encrypt_args(EncryptArgs* en_args,
	                   const char* mode,
	                   const char* key_in,
	                   const char* file_in,
	                   const char* iv_out,
	                   const char* file_out);
void init_decrypt_args(DecryptArgs* dc_args,
	                   const char* mode,
	                   const char* key_in,
	                   const char* file_in,
	                   const char* iv_in,
	                   const char* file_out);


NTSTATUS generate_key(const KeygenArgs* args);
NTSTATUS encrypt_file(const EncryptArgs* args);
NTSTATUS decrypt_file(const DecryptArgs* args);

NTSTATUS set_chain_mode(BCRYPT_ALG_HANDLE h_alg, const char* mode);

void free_encrypt_context(EncryptContext* ctx);
void free_decrypt_context(DecryptContext* ctx);

int read_file(const char* path, BYTE** buffer, DWORD* size);
int write_file(const char* path, BYTE* buffer, DWORD size);

#endif  

