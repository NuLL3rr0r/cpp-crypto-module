// Testbed.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <string>
#include <Windows.h>
#include "Crypto/FileCrypt.hpp"

void PrintUsage(const std::wstring &execName);

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

	std::wstring originalFile(argv[1]);
	std::wstring encryptedFile(argv[2]);
	std::wstring decryptedFile(argv[3]);

	FileCrypt fileCrypt(key, sizeof(key), iv, sizeof(iv));
	std::wstring err;

	if (fileCrypt.Encrypt(originalFile, encryptedFile, err)) {
		if (fileCrypt.Decrypt(encryptedFile, decryptedFile, err)) {
			std::wcout << std::endl;
			std::wcout << err;
			std::wcout << std::endl;
			std::wcout << L"Done!";
			std::wcout << std::endl;
			std::wcout << L"Press Enter to continue...";
			std::cin.ignore();
		} else {
			std::wcout << std::endl;
			std::wcout << err;
			std::wcout << std::endl;
			std::wcout << L"Press Enter to continue...";
			std::cin.ignore();
			return EXIT_FAILURE;
		}
	} else {
		std::wcout << std::endl;
		std::wcout << err;
		std::wcout << std::endl;
		std::wcout << L"Press Enter to continue...";
		std::cin.ignore();
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}

void PrintUsage(const std::wstring &execName)
{
	std::wcout << std::endl << std::endl;
	std::wcout << execName << L" <Original File> <AES/Base64 Encoded File> <Decrypted File>" << std::endl;
	std::wcout << std::endl << std::endl;
}

