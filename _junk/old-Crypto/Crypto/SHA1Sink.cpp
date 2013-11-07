#include "stdafx.h"
#include <stdexcept>
#if defined ( _WIN32 )
#include <windows.h>
//#include <cryptopp/dll.h>     // msvc-shared only
#endif  // defined ( _WIN32 )
#include <cryptopp/ccm.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include "SHA1Sink.hpp"

#define     UNKNOWN_ERROR           "Crypto::SHA1Sink, Unknown error!"

using namespace std;
using namespace CryptoPP;
using namespace Crypto;

SHA1Sink::SHA1Sink()
{
}

SHA1Sink::~SHA1Sink()
{
}

bool SHA1Sink::GenerateHash(const char *text, std::string &out_digest)
{
    string err;
    return GenerateHash(text, out_digest, err);
}

bool SHA1Sink::GenerateHash(const std::string &text, std::string &out_digest)
{
    string err;
    return GenerateHash(text.c_str(), out_digest, err);
}

bool SHA1Sink::GenerateHash(const char *text, std::string &out_digest,
                          std::string &out_error)
{
    try {
        SHA1 hash;

        out_digest.clear();
        StringSource(text, true,
                     new HashFilter(hash, new HexEncoder(new StringSink(out_digest))));

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

bool SHA1Sink::GenerateHash(const std::string &text, std::string &out_digest,
                          std::string &out_error)
{
    return GenerateHash(text.c_str(), out_digest, out_error);
}

