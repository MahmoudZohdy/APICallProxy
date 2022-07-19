#pragma once


#define MAX_PATH 260
#define MAX_SECTION_NAME 100

typedef struct _RegistryKeyQuery {
	WCHAR RegistryKeyToQuery[50];
	WCHAR REgstryKeyPath[500];
} RegistryKeyQuery, * PRegistryKeyQuery;

typedef struct _READWRITEDATA {
	_In_ HANDLE			FileHandle;
	_In_ ULONG			DataLen;
	_In_ LARGE_INTEGER	ByteOffset;	//Start offset in the file for read or write
	unsigned char* Data;
} ReadWriteData, * PReadWriteData;

typedef struct _CreateFileInfo {
	_In_ WCHAR			FileName[MAX_PATH + 16];
	_In_ ACCESS_MASK	DesiredAccess;	//refere to MSDN for information
	_In_ ULONG			ShareAccess;
	_In_ ULONG			CreateDisposition;
} CreateFileInfo, * PCreateFileSInfo;

typedef struct _QuerySystemInformationInfo {
	_In_ ULONG		InformationClass;
	_Inout_ ULONG	DataSize;
	_In_ PVOID		Data;
} QuerySystemInformationInfo, * PQuerySystemInformationInfo;

typedef struct _AllocateVirtualMeomryInfo {
	_In_ HANDLE     ProcessHandle;
	_Inout_ PVOID	BaseAddress;
	_In_ SIZE_T		RegionSize;
	_In_ ULONG		AllocationType;
	_In_ ULONG		Protect;

} AllocateVirtualMeomryInfo, * PAllocateVirtualMeomryInfo;

typedef struct _FreeVirtualMeomryInfo {
	_In_ HANDLE     ProcessHandle;
	_Inout_ PVOID	BaseAddress;

} FreeVirtualMeomryInfo, * PFreeVirtualMeomryInfo;

typedef struct _ReadWriteVirtualMemoryInfo {
	_In_ HANDLE     ProcessHandle;
	_In_ SIZE_T	    DataLen;
	_In_ PVOID		BaseAddress;
	_In_ PVOID		Data;

} ReadWriteVirtualMemoryInfo, * PReadWriteVirtualMemoryInfo;

typedef struct _CreateSectionInfo {
	_In_ ACCESS_MASK     DesiredAccess;
	_In_ LARGE_INTEGER	 SectionMaxSize;
	_In_ WCHAR			 SectionName[MAX_SECTION_NAME];			//Optenal Can Be left Zero
	_In_ ULONG			 SectionPageProtection;
	_In_ ULONG			 AllocationAttribute;
	_In_ HANDLE			 FileHandle;

} CreateSectionInfo, * PCreateSectionInfo;

typedef struct _MapViewOfSectionInfo {
	_In_ HANDLE     SectionHandle;
	_In_ HANDLE		ProcessHandle;
	_In_ PVOID		BaseAddress;
	_In_ SIZE_T		CommetSize;
	_In_ SIZE_T		SizeOfView;
	_In_ ULONG Win32Protect;

} MapViewOfSectionInfo, * PMapViewOfSectionInfo;

typedef struct _UNMapViewOfSectionInfo {
	_In_ HANDLE     ProcessHandle;
	_In_ PVOID		BaseAddress;

} UNMapViewOfSectionInfo, * PUNMapViewOfSectionInfo;

typedef struct _OpenSectionInfo {
	_In_ ACCESS_MASK     DesiredAccess;
	_In_ WCHAR			 SectionName[MAX_SECTION_NAME];			//Optenal Can Be left Zero

} OpenSectionInfo, * POpenSectionInfo;

typedef struct _ThreadContextInfo {
	_In_ DWORD64     ThreadID;
	_In_ CONTEXT	ThreadContext;

} ThreadContextInfo, * PThreadContextInfo;

typedef struct _VirtualProtectInfo {
	_In_ HANDLE		ProcessHandle;
	_In_ PVOID		BaseAddress;
	_In_ SIZE_T		NumberOfBytesToProtect;
	_In_ ULONG		NewAccessProtection;
	OUT  ULONG		OldAccessProtection;

} VirtualProtectInfo, * PVirtualProtectInfo;

typedef struct _QueueUSerApcInfo {
	_In_ HANDLE		ThreadHandle;
	_In_ DWORD64	ProcAddres;
	_In_ PVOID		ArgumentData;

} QueueUSerApcInfo, * PQueueUSerApcInfo;


typedef struct _OpenCreateRegistryInfo {
	_In_ WCHAR			RegistryKeyPath[600];
	_In_ ACCESS_MASK	DesiredAccess;			//refere to MSDN for information
	OUT  ULONG			CreateDisposition;		//Key created or opened ( used only in ZwCreateKey() )

} OpenCreateRegistryInfo, * POpenCreateRegistryInfo;

typedef struct _RegistrySetValueInfo {
	_In_ WCHAR			KeyName[600];
	_In_ HANDLE			KeyHandle;			
	_In_ ULONG			Type;
	_In_ PVOID			Date;
	_In_ ULONG			DateSize;

} RegistrySetValueInfo, * PRegistrySetValueInfo;

typedef struct _RegistryQueryKeyValueInfo {
	_In_ HANDLE			KeyHandle;
	_In_ WCHAR			ValueName[100];
	_In_ ULONG			KeyValueInformationClass;
	_In_ PVOID			Data;
	_In_ ULONG			DateSize;
	_In_ PULONG         ResultLength;

} RegistryQueryKeyValueInfo, * PRegistryQueryKeyValueInfo;

typedef struct _WSAStartCleanUp {
	_In_ PVOID		WskRegistrationPtr;
	_In_ PVOID		WskProviderPtr;
	_In_ PVOID		WskDispatchPtr;

} WSAStartCleanUp, * PWSAStartCleanUp;

typedef struct _SocketStruct {
	_In_ WSAStartCleanUp WSAStartCleanUpptr;
	_In_ INT			 Domain;
	_In_ INT			 Type;
	_In_ INT			 Protocol;
	_In_ ULONG			 Flags;
	OUT PVOID			 Socket;

} SocketStruct, * PSocketStruct;

typedef struct _ConnectStruct {
	_In_ PVOID			  Socket;
	_In_ struct addrinfo* AddrInfo;

} ConnectStruct, * PConnectStruct;


typedef struct _GetAddrInfoStruct {
	_In_    WSAStartCleanUp			 SocketInfo;
	_In_    CHAR*					 Node;
	_In_    CHAR*					 Service;
	_In_    struct addrinfo*		 Hints;
	_Inout_ struct addrinfo**		 Result;

} GetAddrInfoStruct, * PGetAddrInfoStruct;


typedef struct _SendRecvStruct {
	_In_ PVOID    Socket;
	_In_ PVOID	  Buffer;
	_In_ ULONG	  BufferLen;

} SendRecvStruct, * PSendRecvStruct;

typedef struct _SendToRecvFromStruct {
	_In_ PVOID				Socket;
	_In_ PVOID				Buffer;
	_In_ ULONG				BufferLen;
	OUT  struct sockaddr*   AddressInfo;
	OUT  ULONG*			    AddressinfoLen;

} SendToRecvFromStruct, * PSendToRecvFromStruct;

typedef struct _BindStruct {
	_In_ PVOID				 Socket;
	_In_ struct sockaddr*	 Address;

} BindStruct, * PBindStruct;

typedef struct _AcceptStruct {
	_In_ PVOID				    Socket;
	_In_ struct sockaddr_in*	Address;
	OUT INT*					SocketLen;
	OUT  PVOID					NewSocket;
} AcceptStruct, * PAcceptStruct;