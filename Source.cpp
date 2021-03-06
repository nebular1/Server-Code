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

unsigned char userKey[16] = "";
AES_KEY key;

#define DEFAULT_PORT "27015"
void aes_decrypt()
{
	int outlen, inlen;
	FILE *keyfile = fopen("decrypt.txt", "rb");
	unsigned char inbuffer[1024] = "";
	unsigned char outbuffer[1024] = "";
	unsigned char decKey[16] = "";
	fread(decKey, 1, 16, keyfile);
	AES_set_decrypt_key(decKey, 128, &key);
	fclose(keyfile);
	FILE *in = fopen("recvrsa.file", "rb"), *out = fopen("out.txt", "wb");
	fseek(in, 64, SEEK_SET);
	/* äåøèôðóåì ñîäåðæèìîå âõîäíîãî ôàéëà */
	while (1) {
		inlen = fread(inbuffer, 1, 16, in);
		if (inlen <= 0) break;
		AES_decrypt(inbuffer, outbuffer, &key);
		fwrite(outbuffer, 1, 16, out);
	}
	fclose(in);
	fclose(out);

	printf("Ñîäåðæèìîå ôàéëà decrypt.txt áûëî äåøèôðîâàíî è ïîìåùåíî â ôàéë out.txt\n");

}
void Decrypt(char secret[]) {
	RSA * privKey = NULL;
	FILE * privKey_file;
	unsigned char *ptext, *ctext;
	int inlen, outlen;

	/* Îòêðûâàåì êëþ÷åâîé ôàéë è ñ÷èòûâàåì ñåêðåòíûé êëþ÷ */
	OpenSSL_add_all_algorithms();
	privKey_file = fopen("\private.key", "rb");
	privKey = PEM_read_RSAPrivateKey(privKey_file, NULL, NULL, secret);

	/* Îïðåäåëÿåì ðàçìåð êëþ÷à */
	int key_size = RSA_size(privKey);
	ptext = (unsigned char *)malloc(key_size);
	ctext = (unsigned char *)malloc(key_size);
	
		char *buffer;
		std::ifstream fileBuffer("recvrsa.file", std::ios::in | std::ios::binary);
		std::ofstream outputBuffer("aeskey.txt", std::ios::out | std::ios::binary);
		int filelen = 64;
		fileBuffer.seekg(0, std::ios::beg);
		buffer = new char[filelen];
		fileBuffer.read(buffer, filelen);
		outputBuffer.write(buffer, filelen);
		outputBuffer.close();
		fileBuffer.close();

		int out = _open("decrypt.txt", O_CREAT | O_TRUNC | O_RDWR, 0600);
		int in = _open("aeskey.txt", O_RDWR);
		/* Äåøèôðóåì ôàéë */
		while (inlen = _read(in, ctext, key_size)) {
		//inlen = _read(in, ctext, 16);
		//if (inlen <= 0) break;
		outlen = RSA_private_decrypt(inlen, ctext, ptext, privKey, RSA_PKCS1_PADDING);
		_write(out, ptext, outlen);
		memset(ptext, 0, sizeof(ptext));
		}
	printf("Ñîäåðæèìîå ôàéëà recvrsa.file áûëî äåøèôðîâàíî è ïîìåùåíî â ôàéë decrypt.txt\n");

}
void DecryptMenu() {
	char secret[128] = "";
	printf("Ââåäèòå ïàðîëüíóþ ôðàçó äëÿ çàêðûòîãî êëþ÷à: ");
	scanf(secret);
	Decrypt(secret);
	aes_decrypt();
}
int __cdecl main(void)
{
	setlocale(LC_ALL, "Russian");

	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	int iSendResult;
	char recvbuf[BUFSIZE];
	int recvbuflen = BUFSIZE;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
	if (iResult != 0) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// Accept a client socket
	ClientSocket = accept(ListenSocket, NULL, NULL);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	// No longer need server socket
	closesocket(ListenSocket);

	// Receive until the peer shuts down the connection
	Sleep(1000);
	FILE *out = fopen("recvrsa.file", "wt");
	int nSendSize = 1000000;
	while (1)
	{
		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
		fwrite(recvbuf, sizeof(char), iResult, out);
		//fprintf(out, recvbuf);
		if (iResult > 0) {
			printf("Áàéò ïîëó÷åíî: %d\n", iResult);

			/*// Echo the buffer back to the sender
			iSendResult = send(ClientSocket, recvbuf, iResult, 0);
			if (iSendResult == SOCKET_ERROR) {
				printf("send failed with error: %d\n", WSAGetLastError());
				closesocket(ClientSocket);
				WSACleanup();
				return 1;
			}
			printf("Áàéò ïåðåäàíî: %d\n", iSendResult);*/
		}
		else if (iResult == 0) {
			printf("Ñîåäèíåíèå çàêðûòî\n");
			break;
		}
		else {
			printf("recv failed with error: %d\n", WSAGetLastError());
			closesocket(ClientSocket);
			WSACleanup();
			return 1;
		}
		//nSendSize -= iResult;
	} 
	fclose(out);
	// shutdown the connection since we're done
	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		return 1;
	}

	// cleanup
	closesocket(ClientSocket);
	WSACleanup();

	DecryptMenu();

	_getch();
	return 0;
}