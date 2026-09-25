#include<windows.h>
#include<bcrypt.h>
#include<stdio.h>
#include<iostream>

#pragma  comment(lib, "bcrypt.lib")

#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)
#define DATA_TO_ENCRYPT "Data to encrypt i td"


int main() {
	BCRYPT_ALG_HANDLE h_aes_alg = NULL;
	BCRYPT_KEY_HANDLE h_key = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;

	DWORD cb_data = 0;
	DWORD cb_cipher_text = 0;
	DWORD cb_plain_text = 0;
	DWORD cb_key_object = 0;
	DWORD cb_block_len = 0;
	DWORD cb_blob = 0;

	PBYTE pb_cipher_text = NULL;
	PBYTE pb_plain_text = NULL;
	PBYTE pb_key_object = NULL;
	PBYTE pb_iv = NULL;
	PBYTE pb_blob = NULL;

	status = BCryptOpenAlgorithmProvider(
		&h_aes_alg,
		BCRYPT_AES_ALGORITHM,
		NULL,
		false
	);

	status

	std::cout << status << std::endl;
	return 0;
}