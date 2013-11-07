#include "stdafx.h"
#include <stdexcept>
#if defined ( _WIN32 )
#include <windows.h>
//#include <cryptopp/dll.h>     // msvc-shared only
#endif  // defined ( _WIN32 )
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include "AESSink.hpp"

#define     UNKNOWN_ERROR				    "Crypto::AESSink, Unknown error!"
#define     NOT_INITIALIZED_ERROR		    "Crypto::AESSink, Not initialized yet!"

using namespace std;
using namespace CryptoPP;
using namespace Crypto;

AESSink::AESSink()
	: m_isInitialized(false)
{
}

AESSink::AESSink(Key_t key, std::size_t keySize, IV_t iv, std::size_t ivSize)
    : m_key(key),
      m_keySize(keySize),
      m_iv(iv),
      m_ivSize(ivSize),
	  m_isInitialized(true)
{
}

AESSink::~AESSink()
{
}

void AESSink::Initialize(Key_t key, std::size_t keySize, IV_t iv, std::size_t ivSize)
{
	m_key = key;
	m_keySize = keySize;
	m_iv = iv;
	m_ivSize = ivSize;
	m_isInitialized = true;
}

bool AESSink::Encrypt(const char *plainText, std::string &out_encodedText)
{
    string err;
    return Encrypt(plainText, out_encodedText, err);
}

bool AESSink::Encrypt(const std::string &plainText, std::string &out_encodedText)
{
    string err;
    return Encrypt(plainText.c_str(), out_encodedText, err);
}

bool AESSink::Encrypt(const char *plainText, std::string &out_encodedText,
                     std::string &out_error)
{
	if (!m_isInitialized) {
		out_error = NOT_INITIALIZED_ERROR;
		return false;
	}

    try {
        string cipher;

        CBC_Mode<AES>::Encryption enc;
        enc.SetKeyWithIV(m_key, m_keySize, m_iv, m_ivSize);

        cipher.clear();
        StringSource(plainText, true,
                     new StreamTransformationFilter(enc, new StringSink(cipher)));

        out_encodedText.clear();
        StringSource(cipher, true, new HexEncoder(new StringSink(out_encodedText)));

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

bool AESSink::Encrypt(const std::string &plainText, std::string &out_encodedText,
                     std::string &out_error)
{
    return Encrypt(plainText.c_str(), out_encodedText, out_error);
}

bool AESSink::Decrypt(const char *cipherText, std::string &out_recoveredText)
{
    string err;
    return Decrypt(cipherText, out_recoveredText, err);
}

bool AESSink::Decrypt(const std::string &cipherText, std::string &out_recoveredText)
{
    string err;
    return Decrypt(cipherText.c_str(), out_recoveredText, err);
}

bool AESSink::Decrypt(const char *cipherText, std::string &out_recoveredText,
                     std::string &out_error)
{
	if (!m_isInitialized) {
		out_error = NOT_INITIALIZED_ERROR;
		return false;
	}

    try {
        string cipher;

        CBC_Mode<AES>::Decryption dec;
        dec.SetKeyWithIV(m_key, m_keySize, m_iv, m_ivSize);

        cipher.clear();
        StringSource(cipherText, true, new HexDecoder(new StringSink(cipher)));

        out_recoveredText.clear();
        StringSource s(cipher, true,
                       new StreamTransformationFilter(dec, new StringSink(out_recoveredText)));

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

bool AESSink::Decrypt(const std::string &cipherText, std::string &out_recoveredText,
                     std::string &out_error)
{
    return Decrypt(cipherText.c_str(), out_recoveredText, out_error);
}

