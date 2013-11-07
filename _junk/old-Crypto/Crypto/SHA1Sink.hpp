#ifndef SHA1SINK_HPP
#define SHA1SINK_HPP


#include <string>

namespace Crypto {
	class SHA1Sink;
}

class Crypto::SHA1Sink
{
public:
    SHA1Sink();
    ~SHA1Sink();

public:
    bool GenerateHash(const char *text, std::string &out_digest);
    bool GenerateHash(const std::string &text, std::string &out_digest);
    bool GenerateHash(const char *text, std::string &out_digest,
		              std::string &out_error);
    bool GenerateHash(const std::string &text, std::string &out_digest,
		              std::string &out_error);
};


#endif /* SHA1SINK_HPP */


