#ifndef BASE64SINK_HPP
#define BASE64SINK_HPP


#include <string>

namespace Crypto {
	class Base64Sink;
}

class Crypto::Base64Sink
{
public:
    Base64Sink();
    ~Base64Sink();

public:
    int Decode(char value);
    int Decode(const char *code, const int length, char *out_plainText);
    void Decode(std::istream &inputStream, std::ostream &outputStream);
    int Encode(char value);
    int Encode(const char *code, const int length, char *out_plainText);
    int EncodeBlockEnd(char *out_plainText);
    void Encode(std::istream &inputStream, std::ostream &outputStream);
};


#endif /* BASE64SINK_HPP */


