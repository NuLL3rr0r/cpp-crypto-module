#include "stdafx.h"
#include <istream>
#include <ostream>
#include <b64/decode.h>
#include <b64/encode.h>
#include "Base64Sink.hpp"

using namespace std;
using namespace Crypto;

Base64Sink::Base64Sink()
{
}

Base64Sink::~Base64Sink()
{
}

int Base64Sink::Decode(char value)
{
    base64::decoder decoder;
    return decoder.decode(value);
}

int Base64Sink::Decode(const char *code, const int length, char *out_plainText)
{
    base64::decoder decoder;
    return decoder.decode(code, length, out_plainText);
}

void Base64Sink::Decode(std::istream &inputStream, std::ostream &outputStream)
{
    base64::decoder decoder;
    decoder.decode(inputStream, outputStream);
}

int Base64Sink::Encode(char value)
{
    base64::encoder encoder;
    return encoder.encode(value);
}

int Base64Sink::Encode(const char *code, const int length, char *out_plainText)
{
    base64::encoder encoder;
    return encoder.encode(code, length, out_plainText);
}

int Base64Sink::EncodeBlockEnd(char *out_plainText)
{
    base64::encoder encoder;
    return encoder.encode_end(out_plainText);
}

void Base64Sink::Encode(std::istream &inputStream, std::ostream &outputStream)
{
    base64::encoder encoder;
    encoder.encode(inputStream, outputStream);
}

