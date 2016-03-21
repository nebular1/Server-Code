#undef UNICODE

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <conio.h>
#include <iostream>
#include <io.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <fstream>

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")
// #pragma comment (lib, "Mswsock.lib")
#pragma comment(lib, "ssleay32.lib")
#pragma comment(lib, "libeay32.lib")

#define BUFSIZE 1024
#define KEYSIZE 16
#define SECRETSIZE 128
#define KEYBITS 128

unsigned char userKey[KEYSIZE] = "";
AES_KEY key;

#define DEFAULT_PORT "27015"
void aes_decrypt()
{
	int outlen, inlen;
	FILE *keyfile = fopen("decrypt.txt", "rb");
	unsigned char inbuffer[BUFSIZE] = "";
	unsigned char outbuffer[BUFSIZE] = "";
	unsigned char decKey[KEYSIZE] = "";
	fread(decKey, 1, KEYSIZE, keyfile);
	AES_set_decrypt_key(decKey, KEYBITS, &key);
	fclose(keyfile);
	FILE *in = fopen("recvrsa.file", "rb"), *out = fopen("out.txt", "wb");
	fseek(in, 64, SEEK_SET);
	/* дешифруем содержимое входного файла */
	while (1) {
		inlen = fread(inbuffer, 1, KEYSIZE, in);
		if (inlen <= 0) break;
		AES_decrypt(inbuffer, outbuffer, &key);
		fwrite(outbuffer, 1, KEYSIZE, out);
	}
	fclose(in);
	fclose(out);

	printf("File decrypt.txt was decyphered into out.txt file\n");

}

int filelength(char inputname[])
{
	std::ifstream fileBuffer(inputname, std::ios::in | std::ios::binary); //открытие файла для чтения
	fileBuffer.seekg(0, std::ios::end);
	int result = fileBuffer.tellg(); //размер файла
	fileBuffer.close();

	return result;
}

char * binaryread(char inputname[], char outputname[], int len)
{
	char *buffer;
	int filelen;

	if (len == 0)
		filelen = filelength(inputname); //file size
	else
		filelen = len;

	std::ifstream fileBuffer(inputname, std::ios::in | std::ios::binary); //open file for reading

	fileBuffer.seekg(0, std::ios::beg);
	buffer = new char[filelen];
	fileBuffer.read(buffer, filelen); //reading file
	fileBuffer.close();
	if (outputname == 0)
		return buffer;
	else
	{
		std::ofstream outputBuffer(outputname, std::ios::out | std::ios::binary); //open file for writing
		outputBuffer.write(buffer, filelen); //writing to file
		outputBuffer.close();
	}
}

void Decrypt(char secret[]) {
	RSA * privKey = NULL;
	FILE * privKey_file;
	unsigned char *ptext, *ctext;
	int inlen, outlen;

	/* opening key file and reading secret key */
	OpenSSL_add_all_algorithms();
	privKey_file = fopen("\private.key", "rb");
	privKey = PEM_read_RSAPrivateKey(privKey_file, NULL, NULL, secret);

	/* key size */
	int key_size = RSA_size(privKey);
	ptext = (unsigned char *)malloc(key_size);
	ctext = (unsigned char *)malloc(key_size);

	binaryread("recvrsa.file", "aeskey.txt", 64);
		int out = _open("decrypt.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
		int in = _open("aeskey.txt", O_RDWR);
		/* decyphering file */
		while (inlen = _read(in, ctext, key_size)) {
		outlen = RSA_private_decrypt(inlen, ctext, ptext, privKey, RSA_PKCS1_PADDING);
		_write(out, ptext, outlen);
		memset(ptext, 0, sizeof(ptext));
		}
	printf("File recvrsa.file was decyphered into decrypt.txt file\n");

}

void DecryptMenu() {
	char secret[SECRETSIZE] = "";
	printf("Enter your password phrase: ");
	scanf(secret);
	Decrypt(secret); //decypher RSA
	aes_decrypt(); //decypher AES
}

int Socket_Listen(SOCKET sock)
{
	int iResult = listen(sock, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}
}
int Recv_Buf(SOCKET sock, char *rbuf, int rbuflen)
{
	int iResult;
	Sleep(1000);
	FILE *out = fopen("recvrsa.file", "wt");
	int nSendSize = 1000000;
	while (1) // receiving files
	{
		iResult = recv(sock, rbuf, rbuflen, 0);
		fwrite(rbuf, sizeof(char), iResult, out);

		if (iResult > 0) {
			printf("Bytes received: %d\n", iResult);
		}
		else if (iResult == 0) {
			printf("Connection closed\n");
			break;
		}
		else {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(sock);
			WSACleanup();
			return 1;
		}
	}
	fclose(out);
}
int Connect_Shutdown(SOCKET sock)
{
	int iResult = shutdown(sock, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(sock);
		WSACleanup();
		return 1;
	}
}

int __cdecl main(void)
{
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;
	char recvbuf[BUFSIZE];
	int recvbuflen = BUFSIZE;

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData); // Initialize Winsock
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints)); //initializing hints
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result); // Resolve the server address and port
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol); // Create a SOCKET for connecting to server
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen); // listening socket TCP
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	Socket_Listen(ListenSocket); //listening socket
								 
	ClientSocket = accept(ListenSocket, NULL, NULL);  //accepting client socket
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	closesocket(ListenSocket); //closing client socket
	setlocale(LC_ALL, "Russian");
	
	Recv_Buf(ClientSocket, recvbuf, recvbuflen);
	
	Connect_Shutdown(ClientSocket);// connection closing

	closesocket(ClientSocket);	// cleanup
	WSACleanup();

	DecryptMenu(); //decypher

	_getch();
	return 0;
}