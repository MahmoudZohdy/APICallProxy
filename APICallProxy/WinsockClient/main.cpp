#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>

#include "../APICallProxy/IOCTLCodes.h"
#include "../APICallProxy/CommonStruct.h"


int main() {
	BOOL Status = 1;
	DWORD returned;
	WSAStartCleanUp  WSAInfo = { 0 };
	SocketStruct	 SocketInfo = { 0 };
	ConnectStruct	 ConnectInfo = { 0 };

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
	SocketInfo.Flags = WSK_FLAG_CONNECTION_SOCKET;
	SocketInfo.Protocol = IPPROTO_TCP;
	SocketInfo.Type = SOCK_STREAM;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Socket, &SocketInfo, sizeof(SocketStruct), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To Create Connection Socket Error Code: 0x%x\n", GetLastError());
		goto CleanUp;
	}

	printf("[+] Created Connection Socket Successfully\n");


	GetAddrInfoStruct AddrInfo = { 0 };
	struct addrinfo hints = { 0 };
	struct addrinfo* res;

	hints.ai_flags = AI_CANONNAME;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	CHAR Node[] = "127.0.0.1";
	CHAR Service[] = "9095";

	AddrInfo.Hints = &hints;
	AddrInfo.Result = &res;
	AddrInfo.Node = Node;
	AddrInfo.Service = Service;

	AddrInfo.SocketInfo.WskDispatchPtr = WSAInfo.WskDispatchPtr;
	AddrInfo.SocketInfo.WskProviderPtr = WSAInfo.WskProviderPtr;
	AddrInfo.SocketInfo.WskRegistrationPtr = WSAInfo.WskRegistrationPtr;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_GetAddrInfo, &AddrInfo, sizeof(GetAddrInfoStruct), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed to Rsolve Server Addres Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Server Address Resolved Successfully\n");


	ConnectInfo.Socket = SocketInfo.Socket;
	ConnectInfo.AddrInfo = res;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Connect, &ConnectInfo, sizeof(ConnectStruct), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed to Connect To Server Error Code: 0x%x\n", GetLastError());
		goto CleanUp;
	}

	printf("[+] Connected to server Successfully\n");

	INT Counter = 10;
	do {

		SendRecvStruct	 SendInfo = { 0 };
		SendInfo.Socket = SocketInfo.Socket;
		CHAR SendBufer[] = "Hello From Client Side\n";

		SendInfo.Buffer = SendBufer;
		SendInfo.BufferLen = 23;
		Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Send, &SendInfo, sizeof(SendRecvStruct), NULL, NULL, &returned, FALSE);
		if (!Status) {
			printf("[-] Failed to Send to the Servre Error Code: 0x%x\n", GetLastError());
			break;
		}

		printf("[+] Client: %s\n", SendBufer);

		SendRecvStruct RecvInfo = { 0 };
		char RecvBuffer[1024] = { 0 };
		RecvInfo.Socket = SocketInfo.Socket;
		RecvInfo.Buffer = RecvBuffer;
		RecvInfo.BufferLen = 1024;
		Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Recv, &RecvInfo, sizeof(SendRecvStruct), NULL, NULL, &returned, FALSE);
		if (!Status) {
			printf("[-] Failed To Recive Data From Client Side Error Code: 0x%x\n", GetLastError());
			break;
		}
		else {
			printf("[+] Sever: %s\n", RecvBuffer);
		}

		Sleep(500);
		

	} while (Counter--);


CleanUp:

	if (SocketInfo.Socket != NULL) {
		Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CloseSocket, &SocketInfo.Socket, sizeof(PVOID), NULL, NULL, &returned, FALSE);
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