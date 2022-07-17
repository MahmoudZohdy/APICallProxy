#pragma once

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NTSTATUS NTAPI 	PsSuspendProcess(IN PEPROCESS Process);
NTSTATUS NTAPI 	PsResumeProcess(IN PEPROCESS Process);
PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process); // Used to get the base address of process's executable image
NTSTATUS NTAPI MmUnmapViewOfSection(PEPROCESS Process, PVOID BaseAddress); // Used to unmap process's executable image
NTSTATUS  NTAPI ZwOpenThread(PHANDLE ThreadHandle, ACCESS_MASK AccessMask, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

NTSTATUS NTAPI PsGetContextThread(IN PETHREAD Thread, IN OUT PCONTEXT ThreadContext, IN KPROCESSOR_MODE PreviousMode);
NTSTATUS NTAPI PsSetContextThread(IN PETHREAD Thread, IN PCONTEXT ThreadContext, IN KPROCESSOR_MODE PreviousMode);
NTSTATUS ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN PVOID* BaseAddress, IN SIZE_T* NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);


VOID NTAPI KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PETHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ApcMode,
	_In_opt_ PVOID NormalContext
);

BOOLEAN NTAPI KeTestAlertThread(IN  KPROCESSOR_MODE AlertMode);

BOOLEAN NTAPI KeInsertQueueApc(_Inout_ PRKAPC Apc, _In_opt_ PVOID SystemArgument1, _In_opt_ PVOID SystemArgument2, _In_ KPRIORITY Increment);

EXTERN_C_END

// prototypes
void APIProxyUnload(_In_ PDRIVER_OBJECT DriverObject);
NTSTATUS APIProxyCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS APIProxyDeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);


//General.h
NTSTATUS APIProxyCloseHandle(_In_ HANDLE* FileHandle);
NTSTATUS APIProxyAllocateVirtualMemory(_In_ AllocateVirtualMeomryInfo* AllocateMemoryInfo);
NTSTATUS APIProxyProtectVirtualMemory(_In_ VirtualProtectInfo* MemoryProtectionInfo);
NTSTATUS APIProxyReadVirtualMemory(_Out_ ReadWriteVirtualMemoryInfo* ReadMemoryInfo);
NTSTATUS APIProxyWriteVirtualMemory(_In_ ReadWriteVirtualMemoryInfo* WriteMemoryInfo);
NTSTATUS APIProxyQuerySystemInformation(_In_ ULONG InformationClass, _Out_ PVOID InformationData, _In_ ULONG* DataSize);
NTSTATUS APIProxyQueueUserAPC(_In_ QueueUSerApcInfo* APCInfo);
NTSTATUS APIProxyFreeVirtualMemory(_In_ FreeVirtualMeomryInfo* FreeMemoryInfo);
NTSTATUS APIProxyUnLoadDriver(_In_ PUNICODE_STRING DriverRegistryPath);
NTSTATUS APIProxyLoadDriver(_In_ PUNICODE_STRING DriverRegistryPath);

//FileSystem.h
NTSTATUS APIProxyCreateFile(_In_ CreateFileInfo* FileInfo, _Out_ HANDLE* FileHandle);
NTSTATUS APIProxyOpenFile(_In_ CreateFileInfo* FileInfo, _Out_ HANDLE* FileHandle);
NTSTATUS APIProxyDeleteFile(_In_ WCHAR* FileName);
NTSTATUS APIProxyWriteFile(_In_ ReadWriteData* WriteInfo);
NTSTATUS APIProxyReadFile(_Inout_ ReadWriteData* ReadInfo);
NTSTATUS APIProxyGetFileSize(_In_ HANDLE* FileHandle, _Out_ FILE_STANDARD_INFORMATION* FileInfo);
NTSTATUS APIProxyCreateSection(_In_ CreateSectionInfo* SectionInfo, _Out_ HANDLE* SectionHandle);
NTSTATUS APIProxyOpenSection(_In_ OpenSectionInfo* SectionInfo, _Out_ HANDLE* SectionHandle);
NTSTATUS APIProxyMapViewOfSection(_In_ MapViewOfSectionInfo* MapInfo);
NTSTATUS APIProxyUnMapViewOfSection(_In_ UNMapViewOfSectionInfo* UnMapInfo);


//Thread.h
NTSTATUS APIProxyOpenThread(_In_ HANDLE* TID, _Out_ HANDLE* ThreadHandle);
NTSTATUS APIProxySetThreadContext(_In_ ThreadContextInfo* ThreadInfo);
NTSTATUS APIProxyGetThreadContext(_Out_ ThreadContextInfo* ThreadInfo);


//Process.h
NTSTATUS APIProxyTerminateProcess(_In_ DWORD64* PID);
NTSTATUS APIProxyOpenProcess(_In_ HANDLE* PID, _Out_ HANDLE* ProcessHandle);
NTSTATUS APIProxySuspendProcess(_In_ HANDLE* PID);
NTSTATUS APIProxyResumeProcess(_In_ HANDLE* PID);

//Registry.h
NTSTATUS APIProxyCreateKey(_In_ OpenCreateRegistryInfo* CreateKeyInfo, _Out_ HANDLE* NewKeyHandle);
NTSTATUS APIProxyOpenKey(_In_ OpenCreateRegistryInfo* OpenKeyInfo, _Out_ HANDLE* NewKeyHandle);
NTSTATUS APIProxyDeleteRegistryKey(_In_ HANDLE KeyHandle);
NTSTATUS APIProxyRegistrySetValue(_In_ RegistrySetValueInfo* SetValueInfo);
NTSTATUS APIProxyRegistryQueryValue(_In_ RegistryQueryKeyValueInfo* QueryValueInfo);

//Network.h
DWORD32 APIProxyhtonl(DWORD32 hostlong);
unsigned short APIProxyhtons(unsigned short hostshort);
DWORD32 APIProxyntohl(DWORD32 netlong);
unsigned short  APIProxyntohs(unsigned short netshort);
NTSTATUS  APIProxyWSAStartup(OUT WSAStartCleanUp* WSASInfo);
NTSTATUS APIProxyWSACleanup(_In_ WSAStartCleanUp* WSASInfo);
NTSTATUS APIProxtGetAddrInfo(GetAddrInfoStruct* AddrInfo);
NTSTATUS APIProxyFreeAddrInfo(struct addrinfo* AddrInfo);
NTSTATUS APIProxySocket(WSAStartCleanUp* WSAInfo, PKSOCKET* Socket, int Domain, int Type, int Protocol, _In_ ULONG Flags);
NTSTATUS APIProxyCloseSocket(PKSOCKET Socket);
NTSTATUS APIProxyConnect(ConnectStruct* ConnectInfo);
NTSTATUS APIProxyListen();
NTSTATUS APIProxyBind(BindStruct* BindInfo);
NTSTATUS APIProxyAccept(AcceptStruct* AcceptInfo);
NTSTATUS APIProxySend(SendRecvStruct* SendInfo);
NTSTATUS APIProxyRecv(SendRecvStruct* RecvInfo);


//Utility.h
DWORD64  APIProxyGetPIDFromProcessName(WCHAR* ProcessName);
DWORD64  APIProxyGetAnyTIDFromPID(DWORD64 PID);
VOID  APIProxyApcKernelRoutine(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine, _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2);
VOID  APIProxyApcAlertThread(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine, _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2);

DWORD32 APIProxyhtonl(DWORD32 hostlong);
unsigned short APIProxyhtons(unsigned short hostshort);
DWORD32 APIProxyntohl(DWORD32 netlong);
unsigned short APIProxyntohs(unsigned short netshort);

NTSTATUS APIProxyAsyncContextCompletionRoutine(
    _In_ PDEVICE_OBJECT	DeviceObject,
    _In_ PIRP Irp,
    _In_ PKEVENT CompletionEvent
);

NTSTATUS APIProxyAsyncContextAllocate(_Out_ PKSOCKET_ASYNC_CONTEXT AsyncContext);
VOID APIProxyAsyncContextFree(_In_ PKSOCKET_ASYNC_CONTEXT AsyncContext);
VOID APIProxyAsyncContextReset(_In_ PKSOCKET_ASYNC_CONTEXT AsyncContext);

NTSTATUS APIProxyAsyncContextWaitForCompletion(
    _In_ PKSOCKET_ASYNC_CONTEXT AsyncContext,
    _Inout_ PNTSTATUS Status
);

NTSTATUS APIProxyAddrInfoToAddrInfoEx(
    _In_ PADDRINFOA AddrInfo,
    _Out_ PADDRINFOEXW* AddrInfoEx
);

NTSTATUS APIProxyAddrInfoExToAddrInfo(
    _In_ PADDRINFOEXW AddrInfoEx,
    _Out_ PADDRINFOA* AddrInfo
);

VOID APIProxyFreeAddrInfoUtility(_In_ PADDRINFOA AddrInfo);
VOID APIProxyFreeAddrInfoEx(_In_ PADDRINFOEXW AddrInfo);

NTSTATUS KsGetAddrInfo(
    WSAStartCleanUp* WSAInfo,
    _In_ PUNICODE_STRING NodeName,
    _In_ PUNICODE_STRING ServiceName,
    _In_ PADDRINFOEXW Hints,
    _Out_ PADDRINFOEXW* Result
);

VOID KsFreeAddrInfo(
    WSAStartCleanUp* WSAInfo,
    _In_ PADDRINFOEXW AddrInfo
);

NTSTATUS KsCreateSocket(
    WSAStartCleanUp* WSAInfo,
    _Out_ PKSOCKET* Socket,
    _In_ ADDRESS_FAMILY AddressFamily,
    _In_ USHORT SocketType,
    _In_ ULONG Protocol,
    _In_ ULONG Flags
);

NTSTATUS KsCloseSocket(_In_ PKSOCKET Socket);

//TODO: Make the Bind work for all type of socket
NTSTATUS KsBind(_In_ PKSOCKET Socket, _In_ PSOCKADDR LocalAddress);

NTSTATUS KsAccept(
    _In_ PKSOCKET Socket,
    _Out_ PKSOCKET* NewSocket,
    _Out_opt_ PSOCKADDR LocalAddress,
    _Out_opt_ PSOCKADDR RemoteAddress);

NTSTATUS KsConnect(_In_ PKSOCKET Socket, _In_ PSOCKADDR RemoteAddress);

NTSTATUS KsSendRecv(
    _In_ PKSOCKET Socket,
    _In_ PVOID Buffer,
    _Inout_ PULONG Length,
    _In_ ULONG Flags,
    _In_ BOOLEAN Send
);

NTSTATUS KsSend(
    _In_ PKSOCKET Socket,
    _In_ PVOID Buffer,
    _Inout_ PULONG Length,
    _In_ ULONG Flags
);

NTSTATUS KsRecv(
    _In_ PKSOCKET Socket,
    _In_ PVOID Buffer,
    _Inout_ PULONG Length,
    _In_ ULONG Flags
);
