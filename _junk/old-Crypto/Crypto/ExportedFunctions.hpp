#ifndef EXPORTEDFUNCTIONS_HPP
#define EXPORTEDFUNCTIONS_HPP


#include "stdafx.h"
#include "AESSink.hpp"

extern "C"
{
	C_DLLEXPORT	void InitializeAESSink(Crypto::AESSink::Key_t key, std::size_t keySize, Crypto::AESSink::IV_t iv, std::size_t ivSize);
	C_DLLEXPORT	void InitializeBase64Sink();
	C_DLLEXPORT	void InitializeSHA1Sink();

	C_DLLEXPORT	C_BOOL AESEncrypt(const char *plainText, char *out_encodedText);
    C_DLLEXPORT	C_BOOL AESEncryptErr(const char *plainText, char *out_encodedText, char *out_error);
    C_DLLEXPORT	C_BOOL AESDecrypt(const char *cipherText, char *out_recoveredText);
    C_DLLEXPORT	C_BOOL AESDecryptErr(const char *cipherText, char *out_recoveredText, char *out_error);

	C_DLLEXPORT	C_INT Base64DecodeChar(char value);
    C_DLLEXPORT	C_INT Base64Decode(const char *code, const C_INT length, char *out_plainText);
    C_DLLEXPORT	C_INT Base64EncodeChar(char value);
    C_DLLEXPORT	C_INT Base64Encode(const char *code, const C_INT length, char *out_plainText);
    C_DLLEXPORT	C_INT Base64EncodeBlockEnd(char *out_plainText);

	C_DLLEXPORT	C_BOOL SHA1Hash(const char *text, char *out_digest);
    C_DLLEXPORT	C_BOOL SHA1HashErr(const char *text, char *out_digest, char *out_error);
}


#endif /* EXPORTEDFUNCTIONS_HPP */


