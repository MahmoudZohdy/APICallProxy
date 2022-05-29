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
NTSTATUS APIProxyCloseHandle(HANDLE* FileHandle);
NTSTATUS APIProxyAllocateVirtualMemory(AllocateVirtualMeomryInfo* AllocateMemoryInfo);
NTSTATUS APIProxyProtectVirtualMemory(VirtualProtectInfo* MemoryProtectionInfo);
NTSTATUS APIProxyReadVirtualMemory(ReadWriteVirtualMemoryInfo* ReadMemoryInfo);
NTSTATUS APIProxyWriteVirtualMemory(ReadWriteVirtualMemoryInfo* WriteMemoryInfo);
NTSTATUS APIProxyQuerySystemInformation(ULONG InformationClass, PVOID InformationData, ULONG* DataSize);
NTSTATUS APIProxyQueueUserAPC(QueueUSerApcInfo* APCInfo);


//FileSystem.h
NTSTATUS APIProxyCreateFile(CreateFileInfo* FileInfo, HANDLE* FileHandle);
NTSTATUS APIProxyOpenFile(WCHAR* FileInfo, HANDLE* FileHandle);
NTSTATUS APIProxyDeleteFile(WCHAR* FileName);
NTSTATUS APIProxyWriteFile(ReadWriteData* WriteInfo);
NTSTATUS APIProxyReadFile(ReadWriteData* ReadInfo);
NTSTATUS APIProxyGetFileSize(HANDLE* FileHandle, FILE_STANDARD_INFORMATION* FileInfo);
NTSTATUS APIProxyCreateSection(CreateSectionInfo* SectionInfo, HANDLE* SectionHandle);
NTSTATUS APIProxyOpenSection(OpenSectionInfo* SectionInfo, HANDLE* SectionHandle);
NTSTATUS APIProxyMapViewOfSection(MapViewOfSectionInfo* MapInfo);
NTSTATUS APIProxyUnMapViewOfSection(UNMapViewOfSectionInfo* UnMapInfo);


//Thread.h
NTSTATUS APIProxyOpenThread(HANDLE* TID, HANDLE* ThreadHandle);
NTSTATUS APIProxySetThreadContext(ThreadContextInfo* ThreadInfo);
NTSTATUS APIProxyGetThreadContext(ThreadContextInfo* ThreadInfo);


//Process.h
NTSTATUS APIProxyTerminateProcess(DWORD64* PID);
NTSTATUS APIProxyOpenProcess(HANDLE* PID, HANDLE* ProcessHandle);
NTSTATUS APIProxySuspendProcess(HANDLE* PID);
NTSTATUS APIProxyResumeProcess(HANDLE* PID);


//Utility.h
DWORD64 NTAPI APIProxyGetPIDFromProcessName(WCHAR* ProcessName);
DWORD64 NTAPI APIProxyGetAnyTIDFromPID(DWORD64 PID);
VOID NTAPI APIProxyApcKernelRoutine(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine, _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2);
VOID NTAPI APIProxyApcAlertThread(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine, _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2);