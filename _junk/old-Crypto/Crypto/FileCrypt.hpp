#ifndef FILECRYPT_HPP
#define FILECRYPT_HPP


#include <string>

namespace Crypto {
	class FileCrypt;
}

class Crypto::FileCrypt
{
public:
    typedef const unsigned char * Key_t;
    typedef const unsigned char * IV_t;

private:
    Key_t m_key;
    size_t m_keySize;
    IV_t m_iv;
    size_t m_ivSize;
	bool m_isInitialized;

public:
	FileCrypt();
    FileCrypt(Key_t key, std::size_t keySize, IV_t iv, std::size_t ivSize);
    ~FileCrypt();

public:
	void Initialize(Key_t key, std::size_t keySize, IV_t iv, std::size_t ivSize);

    bool Encrypt(const std::string &originalFile, const std::string &encryptedFile);
    bool Encrypt(const std::string &originalFile, const std::string &encryptedFile, std::string &out_error);
    bool Decrypt(const std::string &encryptedFile, const std::string &decryptedFile);
    bool Decrypt(const std::string &encryptedFile, const std::string &decryptedFile, std::string &out_error);
};


#endif /* FILECRYPT_HPP */


