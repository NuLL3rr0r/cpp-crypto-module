#include "stdafx.h"
#include <string>
#include <cstring>
#include "ExportedFunctions.hpp"
#include "FileCrypt.hpp"
#include "Utils.hpp"

#define		NOT_INITIALIZED_ERROR		    L"Not initialized yet!\0"

using namespace Crypto;

C_BOOL isFileCryptInitialized = false;
FileCrypt fileCryptObject;

extern "C"
{
	C_DLLEXPORT	void Initialize(Crypto::FileCrypt::Key_t key, std::size_t keySize, Crypto::FileCrypt::IV_t iv, std::size_t ivSize)
	{
		fileCryptObject.Initialize(key, keySize, iv, ivSize);
		isFileCryptInitialized = true;
	}

    C_DLLEXPORT C_BOOL EncryptMultiByte(const char *originalFile, const char *encryptedFile)
	{
		if (!isFileCryptInitialized)
			return false;

		return fileCryptObject.Encrypt(originalFile, encryptedFile);
	}

    C_DLLEXPORT C_BOOL EncryptMultiByteErr(const char *originalFile, const char *encryptedFile, char *out_error)
	{
		if (!isFileCryptInitialized) {
			std::string err(Utils::WStrToStr(NOT_INITIALIZED_ERROR));
			size_t len = strlen(err.c_str());
			out_error = new char[len];
			strcpy_s(out_error, len, err.c_str());
			return false;
		}

		std::string error;
		C_BOOL rc = fileCryptObject.Encrypt(originalFile, encryptedFile, error);

		size_t len = error.length() + 1;
		out_error = new char[len];
		strcpy_s(out_error, len, error.c_str());

		return rc;
	}

    C_DLLEXPORT C_BOOL DecryptMultiByte(const char *encryptedFile, const char *decryptedFile)
	{
		if (!isFileCryptInitialized)
			return false;

		return fileCryptObject.Decrypt(encryptedFile, decryptedFile);
	}

    C_DLLEXPORT C_BOOL DecryptMultiByteErr(const char *encryptedFile, const char *decryptedFile, char *out_error)
	{
		if (!isFileCryptInitialized) {
			std::string err(Utils::WStrToStr(NOT_INITIALIZED_ERROR));
			size_t len = strlen(err.c_str());
			out_error = new char[len];
			strcpy_s(out_error, len, err.c_str());
			return false;
		}

		std::string error;
		C_BOOL rc = fileCryptObject.Decrypt(encryptedFile, decryptedFile, error);

		size_t len = error.length() + 1;
		out_error = new char[len];
		strcpy_s(out_error, len, error.c_str());

		return rc;
	}

    C_DLLEXPORT C_BOOL EncryptWideChar(const wchar_t *originalFile, const wchar_t *encryptedFile)
	{
		if (!isFileCryptInitialized)
			return false;

		return fileCryptObject.Encrypt(originalFile, encryptedFile);
	}

    C_DLLEXPORT C_BOOL EncryptWideCharErr(const wchar_t *originalFile, const wchar_t *encryptedFile, wchar_t *out_error)
	{
		if (!isFileCryptInitialized) {
			size_t len = wcslen(NOT_INITIALIZED_ERROR);
			out_error = new wchar_t[len];
			wcscpy_s(out_error, len, NOT_INITIALIZED_ERROR);
			return false;
		}

		std::wstring error;
		C_BOOL rc = fileCryptObject.Encrypt(originalFile, encryptedFile, error);

		size_t len = error.length() + 1;
		out_error = new wchar_t[len];
		wcscpy_s(out_error, len, error.c_str());

		return rc;
	}

    C_DLLEXPORT C_BOOL DecryptWideChar(const wchar_t *encryptedFile, const wchar_t *decryptedFile)
	{
		if (!isFileCryptInitialized)
			return false;

		return fileCryptObject.Decrypt(encryptedFile, decryptedFile);
	}

    C_DLLEXPORT C_BOOL DecryptWideCharErr(const wchar_t *encryptedFile, const wchar_t *decryptedFile, wchar_t *out_error)
	{
		if (!isFileCryptInitialized) {
			size_t len = wcslen(NOT_INITIALIZED_ERROR);
			out_error = new wchar_t[len];
			wcscpy_s(out_error, len, NOT_INITIALIZED_ERROR);
			return false;
		}

		std::wstring error;
		C_BOOL rc = fileCryptObject.Decrypt(encryptedFile, decryptedFile, error);

		size_t len = error.length() + 1;
		out_error = new wchar_t[len];
		wcscpy_s(out_error, len, error.c_str());

		return rc;
	}
}

