#ifndef UTILS_HPP
#define UTILS_HPP


#include <string>

namespace Crypto {
	class Utils;
}

class Crypto::Utils
{
public:
	static std::wstring StrToWStr(const std::string &str);
	static std::string WStrToStr(const std::wstring &wstr);
};


#endif /* UTILS_HPP */


