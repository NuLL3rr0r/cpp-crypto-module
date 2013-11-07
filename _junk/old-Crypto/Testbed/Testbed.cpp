// Testbed.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <fstream>
#include <ios>
#include <iostream>
#include <string>
#include <Windows.h>
#include <Crypto/AESSink.hpp>
#include <Crypto/Base64Sink.hpp>
#include <Crypto/FileCrypt.hpp>
#include <Crypto/SHA1Sink.hpp>


std::wstring StrToWStr(const std::string &str);
std::string WStrToStr(const std::wstring &wstr);
void PrintUsage(const std::wstring &execName);
bool ReadFile(const std::string &fileName, size_t &out_size, char *out_data);
bool WriteFile(const std::string &fileName, const char *data);


int _tmain(int argc, _TCHAR **argv)
{
	if (argc != 4) {
		std::wstring execName(L"testbed.exe");
		if (argc > 0) {
            if (argv[0] != NULL) {
                std::wstring fullPath(argv[0]);
				execName = fullPath.substr(fullPath.rfind(L"\\") + 1);
            }
        }
		PrintUsage(execName);
		std::cout << "Press Enter to continue...";
		std::cin.ignore();
		return EXIT_FAILURE;
	}

	const unsigned char key[] = {
		0x4f, 0x39, 0x28, 0x6b, 0x21, 0x31, 0x0, 0x2d, 0x30, 0x6a, 0x23, 0x38, 0x21, 0x2a, 0x3e, 0x69
	};
	const unsigned char iv[] = {
		0x83, 0x23, 0x32, 0x64, 0x34, 0x7f, 0x2f, 0x42, 0x13, 0x34, 0x28, 0x1f, 0x2c, 0x31, 0x0, 0x21
	};

	using namespace Crypto;

	std::string originalFile(WStrToStr(argv[1]));
	std::string encryptedFile(WStrToStr(argv[2]));
	std::string decryptedFile(WStrToStr(argv[3]));

	FileCrypt fileCrypt(key, sizeof(key), iv, sizeof(iv));
	std::string err;

	if (fileCrypt.Encrypt(originalFile, encryptedFile, err)) {
		if (fileCrypt.Decrypt(encryptedFile, decryptedFile, err)) {
			std::cout << std::endl;
			std::cout << err;
			std::cout << std::endl;
			std::cout << "Done!";
			std::cin.ignore();
		} else {
			std::cout << std::endl;
			std::cout << err;
			std::cout << std::endl;
			std::cout << "Press Enter to continue...";
			std::cin.ignore();
			return EXIT_FAILURE;
		}
	} else {
		std::cout << std::endl;
		std::cout << err;
		std::cout << std::endl;
		std::cout << "Press Enter to continue...";
		std::cin.ignore();
		return EXIT_FAILURE;
	}


	/*std::string inFile(WStrToStr(argv[1]));
	std::string outFile(WStrToStr(argv[2]));


	using namespace Crypto;

	size_t inFileSize;
	char *inFileBuffer = NULL;

	if (ReadFile(inFile, inFileSize, inFileBuffer)) {
		const unsigned char key[] = {
			0x4f, 0x39, 0x28, 0x6b, 0x21, 0x31, 0x0, 0x2d, 0x30, 0x6a, 0x23, 0x38, 0x21, 0x2a, 0x3e, 0x69
		};
		const unsigned char iv[] = {
			0x83, 0x23, 0x32, 0x64, 0x34, 0x7f, 0x2f, 0x42, 0x13, 0x34, 0x28, 0x1f, 0x2c, 0x31, 0x0, 0x21
		};

		std::cout << sizeof(key) << " " << sizeof(iv);
		AESSink aes(key, sizeof(key), iv, sizeof(iv));
		std::string err;
		std::string encrypted;

		Base64Sink base64;
		char *encoded = NULL;
		base64.Encode(inFileBuffer, sizeof(inFileBuffer), encoded);
		//WriteFile(outFile + ".base64", encoded);
		//std::cout << encoded << std::endl;


		if (aes.Encrypt(inFileBuffer, encrypted, err)) {
			WriteFile(outFile + ".aes", encrypted.c_str());
			std::cout << encrypted << std::endl;
			return EXIT_SUCCESS;
		} else {
			std::cout << std::endl;
			std::cout << "\t" << err;
			std::cout << std::endl;
			std::cout << "\tPress Enter to continue...";
			std::cin.ignore();
			return EXIT_FAILURE;
		}


		Base64Sink base64;
		char *encoded = NULL;
		base64.Encode(inFileBuffer, sizeof(inFileBuffer), encoded);
		WriteFile(outFile + ".base64", encoded);

		SHA1Sink sha1;
		std::string digest;
		if (sha1.GenerateHash(inFileBuffer, digest, err)) {
			WriteFile(outFile + ".sha1", digest.c_str());
		} else {
			std::cout << std::endl;
			std::cout << "\t" << err;
			std::cout << std::endl;
			std::cout << "\tPress Enter to continue...";
			std::cin.ignore();
			return EXIT_FAILURE;
		}
	} else {
		std::cout << std::endl;
		std::cout << "\tFailed to read input file.";
		std::cout << std::endl;
		std::cout << "\tPress Enter to continue...";
		std::cin.ignore();
		return EXIT_FAILURE;
	}*/

	return EXIT_SUCCESS;
}

std::string WStrToStr(const std::wstring &wstr)
{
    // Convert a Unicode string to an ASCII string
    std::string strTo;
    char *szTo = new char[wstr.length() + 1];
    szTo[wstr.size()] = '\0';
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, szTo, (int)wstr.length(), NULL, NULL);
    strTo = szTo;
    delete[] szTo;
    return strTo;
}

std::wstring StrToWStr(const std::string &str)
{
    // Convert an ASCII string to a Unicode String
    std::wstring wstrTo;
    wchar_t *wszTo = new wchar_t[str.length() + 1];
    wszTo[str.size()] = L'\0';
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, wszTo, (int)str.length());
    wstrTo = wszTo;
    delete[] wszTo;
    return wstrTo;
}

void PrintUsage(const std::wstring &execName)
{
	std::wcout << std::endl << std::endl;
	std::wcout << execName << " <Original File> <AES/Base64 Encoded File> <Decrypted File>" << std::endl;
	std::wcout << std::endl << std::endl;
}

bool ReadFile(const std::string &fileName, size_t &out_size, char *out_data)
{
    char *buffer = NULL;
    out_size = 0;

    std::ifstream file(fileName.c_str(), std::ios::in | std::ios::binary | std::ios::ate);
    if (file.is_open()) {
        std::ifstream::pos_type size;

        size = file.tellg();
        buffer = new char[(int)size];
        file.seekg(0, std::ios::beg);
        file.read(buffer, size);
        file.close();

        out_size = static_cast<size_t>(size);
        out_data = buffer;

		return true;
    }

	return false;
}

bool WriteFile(const std::string &fileName, const char *data)
{
    std::ofstream file(fileName.c_str(), std::ios::out | std::ios::trunc);
    if (file.is_open()) {
        file << data;
        file.close();

		return true;
    }

	return false;
}


