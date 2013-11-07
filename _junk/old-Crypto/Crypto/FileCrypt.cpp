#include "stdafx.h"
#include <stdexcept>
#if defined ( _WIN32 )
#include <windows.h>
//#include <cryptopp/dll.h>     // msvc-shared only
#endif  // defined ( _WIN32 )
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/files.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include "FileCrypt.hpp"

#define     UNKNOWN_ERROR				    "Crypto::FileCrypt, Unknown error!"
#define     NOT_INITIALIZED_ERROR		    "Crypto::FileCrypt, Not initialized yet!"

using namespace std;
using namespace CryptoPP;
using namespace Crypto;

FileCrypt::FileCrypt()
	: m_isInitialized(false)
{
}

FileCrypt::FileCrypt(Key_t key, std::size_t keySize, IV_t iv, std::size_t ivSize)
    : m_key(key),
      m_keySize(keySize),
      m_iv(iv),
      m_ivSize(ivSize),
	  m_isInitialized(true)
{
}

FileCrypt::~FileCrypt()
{
}

void FileCrypt::Initialize(Key_t key, std::size_t keySize, IV_t iv, std::size_t ivSize)
{
	m_key = key;
	m_keySize = keySize;
	m_iv = iv;
	m_ivSize = ivSize;
	m_isInitialized = true;
}

bool FileCrypt::Encrypt(const std::string &originalFile, const std::string &encryptedFile)
{
	string err;
	return Encrypt(originalFile, encryptedFile, err);
}

bool FileCrypt::Encrypt(const std::string &originalFile, const std::string &encryptedFile, std::string &out_error)
{
	if (!m_isInitialized) {
		out_error = NOT_INITIALIZED_ERROR;
		return false;
	}

    try {
        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(m_key, m_keySize, m_iv, m_ivSize);

		FileSource(originalFile.c_str(), true,
			new StreamTransformationFilter(enc,
			new HexEncoder(
			new FileSink(encryptedFile.c_str()))));

        return true;
    }

    catch (CryptoPP::Exception &ex) {
        out_error.assign(ex.what());
    }

    catch (std::exception &ex) {
        out_error.assign(ex.what());
    }

    catch (...) {
        out_error.assign(UNKNOWN_ERROR);
    }

    return false;
}

bool FileCrypt::Decrypt(const std::string &encryptedFile, const std::string &decryptedFile)
{
	string err;
	return Decrypt(encryptedFile, decryptedFile, err);
}

bool FileCrypt::Decrypt(const std::string &encryptedFile, const std::string &decryptedFile, std::string &out_error)
{
		if (!m_isInitialized) {
		out_error = NOT_INITIALIZED_ERROR;
		return false;
	}

    try {
        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(m_key, m_keySize, m_iv, m_ivSize);

		string cipher;
		FileSource(encryptedFile.c_str(), true,
			new HexDecoder(new StringSink(cipher)));

		StringSource(cipher, true,
			new StreamTransformationFilter(dec,
			new FileSink(decryptedFile.c_str())));

        return true;
    }

    catch (CryptoPP::Exception &ex) {
        out_error.assign(ex.what());
    }

    catch (std::exception &ex) {
        out_error.assign(ex.what());
    }

    catch (...) {
        out_error.assign(UNKNOWN_ERROR);
    }

    return false;
}


