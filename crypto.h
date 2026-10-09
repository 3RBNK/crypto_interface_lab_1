#ifndef CRYPTO_H
#define CRYPTO_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <windows.h>
#include <bcrypt.h>

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

#define AES_KEY_SIZE 16
#define AES_BLOCK_SIZE 16
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define STATUS_SUCCESS ((NTSTATUS)0xC00000000)


typedef struct {
	const char* key_out;
} KeygenArgs;


typedef struct {
	const char* mode;
	const char* key_in;
	const char* file_in;
	const char* iv_out;
	const char* file_out;
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
	const char* mode;
	const char* key_in;
	const char* file_in;
	const char* iv_in;
	const char* file_out;
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

/* One complete CFB-128 message; output must have input_size bytes. */
NTSTATUS crypt_cfb128(BCRYPT_KEY_HANDLE h_key, BYTE* input, DWORD input_size,
                     const BYTE* iv, BYTE* output, int decrypting);

void free_encrypt_context(EncryptContext* ctx);
void free_decrypt_context(DecryptContext* ctx);

int read_file(const char* path, BYTE** buffer, DWORD* size);
int write_file(const char* path, BYTE* buffer, DWORD size);

#endif  

