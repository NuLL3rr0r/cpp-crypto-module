#ifndef EXPORTEDFUNCTIONS_HPP
#define EXPORTEDFUNCTIONS_HPP


#include "stdafx.h"
#include "FileCrypt.hpp"

extern "C"
{
	C_DLLEXPORT	void Initialize(Crypto::FileCrypt::Key_t key, std::size_t keySize, Crypto::FileCrypt::IV_t iv, std::size_t ivSize);

    C_DLLEXPORT C_BOOL EncryptMultiByte(const char *originalFile, const char *encryptedFile);
    C_DLLEXPORT C_BOOL EncryptMultiByteErr(const char *originalFile, const char *encryptedFile, char *out_error);
    C_DLLEXPORT C_BOOL DecryptMultiByte(const char *encryptedFile, const char *decryptedFile);
    C_DLLEXPORT C_BOOL DecryptMultiByteErr(const char *encryptedFile, const char *decryptedFile, char *out_error);

    C_DLLEXPORT C_BOOL EncryptWideChar(const wchar_t *originalFile, const wchar_t *encryptedFile);
    C_DLLEXPORT C_BOOL EncryptWideCharErr(const wchar_t *originalFile, const wchar_t *encryptedFile, wchar_t *out_error);
    C_DLLEXPORT C_BOOL DecryptWideChar(const wchar_t *encryptedFile, const wchar_t *decryptedFile);
    C_DLLEXPORT C_BOOL DecryptWideCharErr(const wchar_t *encryptedFile, const wchar_t *decryptedFile, wchar_t *out_error);
}


#endif /* EXPORTEDFUNCTIONS_HPP */


