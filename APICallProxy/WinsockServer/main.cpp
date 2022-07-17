#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>

#include "../APICallProxy/IOCTLCodes.h"
#include "../APICallProxy/CommonStruct.h"

//used only for htons()
#pragma comment(lib, "Ws2_32.lib")


int main() {
	BOOL Status = 1;
	DWORD returned;
	WSAStartCleanUp  WSAInfo = { 0 };
	SocketStruct	 SocketInfo = { 0 };
	SendRecvStruct	 SendInfo = { 0 };
	BindStruct		 BindInfo = { 0 };
	AcceptStruct	 AcceptInfo = { 0 };


	HANDLE hDevice = CreateFile(L"\\\\.\\APICallProxy", GENERIC_WRITE, FILE_SHARE_WRITE, FALSE, OPEN_EXISTING, 0, FALSE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[-] Failed To Open Driver Error Code: 0x%x\n", GetLastError());
		return 0;
	}


	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_WSAStartup, &WSAInfo, sizeof(WSAStartCleanUp), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed to initiates Winsock Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] initiates of the Winsock Successfully\n");



	SocketInfo.WSAStartCleanUpptr.WskDispatchPtr = WSAInfo.WskDispatchPtr;
	SocketInfo.WSAStartCleanUpptr.WskProviderPtr = WSAInfo.WskProviderPtr;
	SocketInfo.WSAStartCleanUpptr.WskRegistrationPtr = WSAInfo.WskRegistrationPtr;

#define WSK_FLAG_BASIC_SOCKET        0x00000000
#define WSK_FLAG_LISTEN_SOCKET       0x00000001
#define WSK_FLAG_CONNECTION_SOCKET   0x00000002
#define WSK_FLAG_DATAGRAM_SOCKET     0x00000004
#define WSK_FLAG_STREAM_SOCKET       0x00000008

	SocketInfo.Domain = AF_INET;
	SocketInfo.Flags = WSK_FLAG_LISTEN_SOCKET;
	SocketInfo.Protocol = IPPROTO_TCP;
	SocketInfo.Type = SOCK_STREAM;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Socket, &SocketInfo, sizeof(SocketStruct), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To Create Listen Socket Error Code: 0x%x\n", GetLastError());
		goto CleanUp;
	}

	printf("[+] Created Listen Socket Successfully\n");


	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(9095);

	BindInfo.Socket = SocketInfo.Socket;
	BindInfo.Address = &addr;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Bind, &BindInfo, sizeof(BindStruct), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed to Bind Socket Error Code: 0x%x\n", GetLastError());
		goto CleanUp;
	}

	printf("[+] Binding Socket Successfully\n");


	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_listen, NULL, NULL, NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed to Listen on Socket Error Code: 0x%x\n", GetLastError());
		goto CleanUp;
	}

	printf("[+] Listen on Socket Successfully\n");

	INT SocLen = 0;
	AcceptInfo.Socket = SocketInfo.Socket;
	AcceptInfo.Address = &addr;
	AcceptInfo.SocketLen = &SocLen;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Accept, &AcceptInfo, sizeof(AcceptStruct), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed to Accept Connection Error Code: 0x%x\n", GetLastError());
		goto CleanUp;
	}

	printf("[+] Connection Accepted Successfully\n");


	do {

		SendRecvStruct RecvInfo = { 0 };
		char RecvBuffer[1024] = { 0 };
		RecvInfo.Socket = AcceptInfo.NewSocket;
		RecvInfo.Buffer = RecvBuffer;
		RecvInfo.BufferLen = 1024;
		Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Recv, &RecvInfo, sizeof(SendRecvStruct), NULL, NULL, &returned, FALSE);
		if (!Status) {
			printf("[-] Failed To Recive Data From Client Side Error Code: 0x%x\n", GetLastError());
			break;
		}
		
		printf("[+] Client: %s\n", RecvBuffer);


		SendInfo.Socket = AcceptInfo.NewSocket;
		CHAR SendBufer[] = "Hello From Server Side\n";

		SendInfo.Buffer = SendBufer;
		SendInfo.BufferLen = 23;
		Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Send, &SendInfo, sizeof(SendRecvStruct), NULL, NULL, &returned, FALSE);
		if (!Status) {
			printf("[-] Failed to Replay to the Client Error Code: 0x%x\n", GetLastError());
			break;
		}
		else {
			printf("[+] Server: %s\n", SendBufer);
		}

	} while (1);


	CleanUp:
	
	if (SocketInfo.Socket != NULL) {
		Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CloseSocket, &SocketInfo.Socket, sizeof(PVOID), NULL, NULL, &returned, FALSE);
		if (!Status) {
			printf("[-] Failed Close Socket Error Code: 0x%x\n", GetLastError());
		}
	}

	if (AcceptInfo.NewSocket != NULL) {
		Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CloseSocket, &AcceptInfo.NewSocket, sizeof(PVOID), NULL, NULL, &returned, FALSE);
		if (!Status) {
			printf("[-] Failed Close Socket Error Code: 0x%x\n", GetLastError());
		}
	}

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_WSACleanup, &WSAInfo, sizeof(WSAStartCleanUp), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To Terminates use of the Winsock Error Code: 0x%x\n", GetLastError());
	}

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &WSAInfo, sizeof(WSAStartCleanUp), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To Terminates use of the Winsock Error Code: 0x%x\n", GetLastError());
	}

	return 0;
}