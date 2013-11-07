#include "stdafx.h"
#include <string>
#include <cstring>
#include "Base64Sink.hpp"
#include "SHA1Sink.hpp"
#include "ExportedFunctions.hpp"

#define		NOT_INITIALIZED_ERROR		    "Not initialized yet!\0"

using namespace Crypto;

C_BOOL isAESSinkInitialized = false;
C_BOOL isBase64SinkInitialized = false;
C_BOOL isSHA1SinkInitialized = false;

AESSink aesSinkObject;
Base64Sink base64SinkObject;
SHA1Sink sha1SinkObject;

extern "C"
{
	C_DLLEXPORT	void InitializeAESSink(Crypto::AESSink::Key_t key, std::size_t keySize, Crypto::AESSink::IV_t iv, std::size_t ivSize)
	{
		aesSinkObject.Initialize(key, keySize, iv, ivSize);
		isAESSinkInitialized = true;
	}

	C_DLLEXPORT	void InitializeBase64Sink()
	{
		isBase64SinkInitialized = true;
	}

	C_DLLEXPORT	void InitializeSHA1Sink()
	{
		isSHA1SinkInitialized = true;
	}

	C_DLLEXPORT	C_BOOL AESEncrypt(const char *plainText, char *out_encodedText)
	{
		if (!isAESSinkInitialized)
			return false;

		std::string encoded;
		C_BOOL rc = aesSinkObject.Encrypt(plainText, encoded);

		out_encodedText = new char[encoded.length() + 1];
		strcpy_s(out_encodedText, encoded.length() + 1, encoded.c_str());

		return rc;
	}

    C_DLLEXPORT	C_BOOL AESEncryptErr(const char *plainText, char *out_encodedText, char *out_error)
	{
		if (!isAESSinkInitialized) {
			size_t len = sizeof(NOT_INITIALIZED_ERROR);
			out_error = new char[len];
			strcpy_s(out_error, len, NOT_INITIALIZED_ERROR);
			return false;
		}

		std::string encoded;
		std::string error;
		C_BOOL rc = aesSinkObject.Encrypt(plainText, encoded);

		out_encodedText = new char[encoded.length() + 1];
		out_error = new char[error.length() + 1];
		strcpy_s(out_encodedText, encoded.length() + 1, encoded.c_str());
		strcpy_s(out_error, error.length() + 1, error.c_str());

		return rc;
	}

    C_DLLEXPORT	C_BOOL AESDecrypt(const char *cipherText, char *out_recoveredText)
	{
		if (!isAESSinkInitialized)
			return false;

		std::string recovered;
		C_BOOL rc = aesSinkObject.Decrypt(cipherText, recovered);

		out_recoveredText = new char[recovered.length() + 1];
		strcpy_s(out_recoveredText, recovered.length() + 1, recovered.c_str());

		return rc;
	}

    C_DLLEXPORT	C_BOOL AESDecryptErr(const char *cipherText, char *out_recoveredText, char *out_error)
	{
		if (!isAESSinkInitialized) {
			size_t len = sizeof(NOT_INITIALIZED_ERROR);
			out_error = new char[len];
			strcpy_s(out_error, len, NOT_INITIALIZED_ERROR);
			return false;
		}

		std::string recovered;
		std::string error;
		C_BOOL rc = aesSinkObject.Decrypt(cipherText, recovered);

		out_recoveredText = new char[recovered.length() + 1];
		out_error = new char[error.length() + 1];
		strcpy_s(out_recoveredText, recovered.length() + 1, recovered.c_str());
		strcpy_s(out_error, error.length() + 1, error.c_str());

		return rc;
	}

	C_DLLEXPORT	C_INT Base64DecodeChar(char value)
	{
		return base64SinkObject.Decode(value);
	}

    C_DLLEXPORT	C_INT Base64Decode(const char *code, const C_INT length, char *out_plainText)
	{
		return base64SinkObject.Decode(code, length, out_plainText);
	};

    C_DLLEXPORT	C_INT Base64EncodeChar(char value)
	{
		return base64SinkObject.Encode(value);
	}

    C_DLLEXPORT	C_INT Base64Encode(const char *code, const C_INT length, char *out_plainText)
	{
		return base64SinkObject.Encode(code, length, out_plainText);
	}

    C_DLLEXPORT	C_INT Base64EncodeBlockEnd(char *out_plainText)
	{
		return base64SinkObject.EncodeBlockEnd(out_plainText);
	}

	C_DLLEXPORT	C_BOOL SHA1Hash(const char *text, char *out_digest)
	{
		if (!isSHA1SinkInitialized)
			return false;

		std::string digest;
		C_BOOL rc = sha1SinkObject.GenerateHash(text, digest);

		out_digest = new char[digest.length() + 1];
		strcpy_s(out_digest, digest.length() + 1, digest.c_str());

		return rc;
	}

    C_DLLEXPORT	C_BOOL SHA1HashErr(const char *text, char *out_digest, char *out_error)
	{
		if (!isSHA1SinkInitialized) {
			size_t len = sizeof(NOT_INITIALIZED_ERROR);
			out_error = new char[len];
			strcpy_s(out_error, len, NOT_INITIALIZED_ERROR);
			return false;
		}

		std::string digest;
		std::string error;
		C_BOOL rc = sha1SinkObject.GenerateHash(text, digest, error);

		out_digest = new char[digest.length() + 1];
		out_error = new char[error.length() + 1];
		strcpy_s(out_digest, digest.length() + 1, digest.c_str());
		strcpy_s(out_error, error.length() + 1, error.c_str());

		return rc;
	}
}

