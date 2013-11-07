#ifndef AESSINK_HPP
#define AESSINK_HPP


#include <string>

namespace Crypto {
	class AESSink;
}

class Crypto::AESSink
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
    AESSink();
    AESSink(Key_t key, std::size_t keySize, IV_t iv, std::size_t ivSize);
    ~AESSink();

public:
	void Initialize(Key_t key, std::size_t keySize, IV_t iv, std::size_t ivSize);

    bool Encrypt(const char *plainText, std::string &out_encodedText);
    bool Encrypt(const std::string &plainText, std::string &out_encodedText);
    bool Encrypt(const char *plainText, std::string &out_encodedText,
                 std::string &out_error);
    bool Encrypt(const std::string &plainText, std::string &out_encodedText,
                 std::string &out_error);
    bool Decrypt(const char *cipherText, std::string &out_recoveredText);
    bool Decrypt(const std::string &cipherText, std::string &out_recoveredText);
    bool Decrypt(const char *cipherText, std::string &out_recoveredText,
                 std::string &out_error);
    bool Decrypt(const std::string &cipherText, std::string &out_recoveredText,
                 std::string &out_error);
};


#endif /* AESSINK_HPP */


