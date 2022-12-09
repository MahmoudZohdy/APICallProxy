#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <wsk.h>
#include "IOCTLCodes.h"
#include "Struct.h"
#include "CommonStruct.h"
#include "Prototypes.h"
#include "Utility.h"
#include "FileSystem.h"
#include "Process.h"
#include "Thread.h"
#include "Registry.h"
#include "Network.h"
#include "General.h"


// DriverEntry
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = APIProxyUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = APIProxyCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = APIProxyCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = APIProxyDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\APICallProxy");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create device (0x%08X)\n", status);
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\APICallProxy");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	return status;
}

void APIProxyUnload(_In_ PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\APICallProxy");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);

	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);

}

_Use_decl_annotations_
NTSTATUS APIProxyCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS APIProxyDeviceControl(PDEVICE_OBJECT, PIRP Irp) {

	auto stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG DataWritten = 0;
	ULONG IoctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
	auto DataSize = stack->Parameters.DeviceIoControl.InputBufferLength;
	auto OutDataSize = stack->Parameters.DeviceIoControl.OutputBufferLength;
	auto UserData = (PVOID*)stack->Parameters.DeviceIoControl.Type3InputBuffer;
	auto OutBuffer = (PVOID*)Irp->UserBuffer;

	__try {
		// check the user buffer, as the default methd is NEITHER
		ProbeForRead(UserData, DataSize, sizeof(UCHAR));
		ProbeForWrite(OutBuffer, OutDataSize, sizeof(UCHAR));
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = STATUS_ACCESS_VIOLATION;
		goto Finish;
	}

	switch (IoctlCode) {
		//the return status doese not represent if the file was overwritten or created use openfile to check if file present first
	case IOCTL_API_PROXY_CREATEFILE:
	{
		if (DataSize < sizeof(CreateFileInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		HANDLE FileHandle = NULL;

		Status = APIProxyCreateFile((CreateFileInfo*)UserData, &FileHandle);

		HANDLE* Output = (HANDLE*)OutBuffer;
		*Output = FileHandle;

		DataWritten = sizeof(HANDLE);

	}
	break;

	case IOCTL_API_PROXY_OPENFILE:
	{
		auto FileInfo = (CreateFileInfo*)UserData;

		HANDLE FileHandle = NULL;
		Status = APIProxyOpenFile(FileInfo, &FileHandle);

		HANDLE* Output = (HANDLE*)OutBuffer;
		*Output = FileHandle;

		DataWritten = sizeof(HANDLE);

	}

	break;


	case IOCTL_API_PROXY_DELETEFILE:
	{
		auto FileName = (WCHAR*)UserData;
		Status = APIProxyDeleteFile(FileName);
	}

	break;

	case IOCTL_API_PROXY_CLOSE_HANDLE:
	{
		auto FileHandle = (HANDLE*)UserData;

		if (DataSize < sizeof(HANDLE)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyCloseHandle(FileHandle);

	}
	break;

	case IOCTL_API_PROXY_WRITEFILE:
	{
		auto WriteInfo = (ReadWriteData*)UserData;

		if (DataSize < sizeof(ReadWriteData)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyWriteFile(WriteInfo);

	}
	break;

	case IOCTL_API_PROXY_READFILE:
	{
		auto ReadInfo = (ReadWriteData*)UserData;

		if (DataSize < sizeof(ReadWriteData)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyReadFile(ReadInfo);

	}

	break;

	case IOCTL_API_PROXY_GET_FILE_SIZE_FROM_HANDLE:
	{
		auto FileHandle = (HANDLE*)UserData;
		FILE_STANDARD_INFORMATION FileInfo{};

		if (DataSize < sizeof(HANDLE)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyGetFileSize(FileHandle, &FileInfo);

		RtlCopyMemory(OutBuffer, &(FileInfo.EndOfFile), sizeof(LARGE_INTEGER));

		DataWritten = sizeof(LARGE_INTEGER);

	}
	break;

	case IOCTL_API_PROXY_TERMINATE_PROCESS:
	{
		auto PID = (DWORD64*)UserData;

		if (DataSize < sizeof(DWORD64)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyTerminateProcess(PID);

	}
	break;

	case IOCTL_API_PROXY_GET_PID_FROM_PROCESSNAME:
	{
		auto ProcessName = (WCHAR*)UserData;

		if (DataSize == 0) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		DWORD64 PID = APIProxyGetPIDFromProcessName(ProcessName);
		if (PID == 0) {
			Status = STATUS_UNSUCCESSFUL;
		}

		DWORD64* Output = (DWORD64*)OutBuffer;
		*Output = PID;

		DataWritten = sizeof(DWORD64);

	}
	break;

	case IOCTL_API_PROXY_OPEN_PROCESS:
	{
		auto PID = (DWORD64*)UserData;
		HANDLE ProcessHandle = NULL;

		if (DataSize < sizeof(DWORD64)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyOpenProcess((HANDLE*)PID, &ProcessHandle);

		HANDLE* Output = (HANDLE*)OutBuffer;
		*Output = ProcessHandle;

		DataWritten = sizeof(HANDLE);

	}
	break;

	case IOCTL_API_PROXY_OPEN_THREAD:
	{
		auto TID = (HANDLE*)UserData;
		HANDLE ThreadHandle = NULL;

		if (DataSize < sizeof(HANDLE)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyOpenThread(TID, &ThreadHandle);

		HANDLE* Output = (HANDLE*)OutBuffer;
		*Output = ThreadHandle;

		DataWritten = sizeof(HANDLE);

	}
	break;

	case IOCTL_API_PROXY_QUERY_SYSTEM_INFORMATION:
	{
		auto SystemInfo = (QuerySystemInformationInfo*)UserData;

		if (DataSize < sizeof(QuerySystemInformationInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyQuerySystemInformation(SystemInfo->InformationClass, SystemInfo->Data, &SystemInfo->DataSize);

	}
	break;

	case IOCTL_API_PROXY_CREATE_REMOTE_THREAD:
	{

		// TODO
	}

	break;

	case IOCTL_API_PROXY_CREATE_THREAD:
	{

		
	}

	break;

	case IOCTL_API_PROXY_ALLOCATE_MEMORY_IN_PROCESS_USING_HANDLE:
	{
		auto AllocateMemoryInfo = (AllocateVirtualMeomryInfo*)UserData;

		if (DataSize < sizeof(AllocateVirtualMeomryInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyAllocateVirtualMemory(AllocateMemoryInfo);
	}

	break;

	case IOCTL_API_PROXY_FREE_MEMORY_IN_PROCESS_USING_HANDLE:
	{
		auto FreeMemoryInfo = (FreeVirtualMeomryInfo*)UserData;

		if (DataSize < sizeof(FreeVirtualMeomryInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}
		Status = APIProxyFreeVirtualMemory(FreeMemoryInfo);
	}

	break;

	case IOCTL_API_PROXY_WRITE_PROCESS_MEMORY:
	{
		auto WriteMemoryInfo = (ReadWriteVirtualMemoryInfo*)UserData;

		if (DataSize < sizeof(ReadWriteVirtualMemoryInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyWriteVirtualMemory(WriteMemoryInfo);
	}

	break;

	case IOCTL_API_PROXY_READ_PROCESS_MEMORY:
	{
		auto ReadMemoryInfo = (ReadWriteVirtualMemoryInfo*)UserData;

		if (DataSize < sizeof(ReadWriteVirtualMemoryInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyReadVirtualMemory(ReadMemoryInfo);
	}

	break;

	case IOCTL_API_PROXY_SUSPEND_PROCESS:
	{
		auto ProcessHandle = (HANDLE*)UserData;

		if (DataSize < sizeof(HANDLE)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxySuspendProcess(ProcessHandle);
	}

	break;

	case IOCTL_API_PROXY_RESUME_PROCESS:
	{
		auto ProcessHandle = (HANDLE*)UserData;

		if (DataSize < sizeof(HANDLE)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyResumeProcess(ProcessHandle);
	}

	break;

	case IOCTL_API_PROXY_SUSPEND_THREAD:
	{
		// TODO

	}

	break;

	case IOCTL_API_PROXY_RESUME_THREAD:
	{
		// TODO

	}

	break;

	case IOCTL_API_PROXY_CREATE_SECTION:
	{
		auto SectionInfo = (CreateSectionInfo*)UserData;
		HANDLE SectionHandle = NULL;

		if (DataSize < sizeof(CreateSectionInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyCreateSection(SectionInfo, &SectionHandle);

		HANDLE* Output = (HANDLE*)OutBuffer;
		*Output = SectionHandle;

		DataWritten = sizeof(HANDLE);
	}

	break;

	case IOCTL_API_PROXY_MAP_VIEW_OF_SECTION:
	{
		auto MapInfo = (MapViewOfSectionInfo*)UserData;

		if (DataSize < sizeof(MapViewOfSectionInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyMapViewOfSection(MapInfo);
	}

	break;

	case IOCTL_API_PROXY_UNMAP_VIEW_OF_SECTION:
	{
		auto UnMapInfo = (UNMapViewOfSectionInfo*)UserData;

		if (DataSize < sizeof(UNMapViewOfSectionInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyUnMapViewOfSection(UnMapInfo);
	}

	break;

	case IOCTL_API_PROXY_OPEN_SECTION:
	{
		auto SectionInfo = (OpenSectionInfo*)UserData;
		HANDLE SectionHandle = NULL;

		if (DataSize < sizeof(OpenSectionInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyOpenSection(SectionInfo, &SectionHandle);

		HANDLE* Output = (HANDLE*)OutBuffer;
		*Output = SectionHandle;

		DataWritten = sizeof(HANDLE);

	}

	break;

	case IOCTL_API_PROXY_SET_THREAD_CONTEXT:
	{
		auto ThreadInfo = (ThreadContextInfo*)UserData;

		if (DataSize < sizeof(ThreadContextInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxySetThreadContext(ThreadInfo);
	}

	break;

	case IOCTL_API_PROXY_GET_THREAD_CONTEXT:
	{
		auto ThreadInfo = (ThreadContextInfo*)UserData;

		if (DataSize < sizeof(ThreadContextInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyGetThreadContext(ThreadInfo);
	}

	break;

	case IOCTL_API_PROXY_VIRTUAL_PROTECT:
	{
		auto MemoryProtectionInfo = (VirtualProtectInfo*)UserData;

		if (DataSize < sizeof(VirtualProtectInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyProtectVirtualMemory(MemoryProtectionInfo);
	}

	break;

	case IOCTL_API_PROXY_QUEUE_APC:
	{
		auto APCInfo = (QueueUSerApcInfo*)UserData;

		if (DataSize < sizeof(QueueUSerApcInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyQueueUserAPC(APCInfo);
	}

	break;

	case IOCTL_API_PROXY_LOAD_DRIVER:
	{
		auto UserRegPath = (WCHAR*)UserData;
		UNICODE_STRING RegPath;

		// must copy the registry path from User Mode buffer to Kernel mode buffer (the method used in communication is METHOD_NEITHER)
		WCHAR SystemRegPath[500];
		wcscpy(SystemRegPath, UserRegPath);

		RtlInitUnicodeString(&RegPath, SystemRegPath);
		Status = APIProxyLoadDriver(&RegPath);

	}
	break;

	case IOCTL_API_PROXY_UNLOAD_DRIVER:
	{
		auto UserRegPath = (WCHAR*)UserData;
		UNICODE_STRING RegPath;

		RtlInitUnicodeString(&RegPath, UserRegPath);
		Status = APIProxyUnLoadDriver(&RegPath);

	}
	break;

	case IOCTL_API_PROXY_CREATE_REGISTRY_KEY:
	{
		auto CreateRegInfo = (OpenCreateRegistryInfo*)UserData;
		HANDLE NewKeyHandle = NULL;

		if (DataSize < sizeof(OpenCreateRegistryInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyCreateKey(CreateRegInfo, &NewKeyHandle);
		
		HANDLE* Output = (HANDLE*)OutBuffer;
		*Output = NewKeyHandle;

	}
	break;

	case IOCTL_API_PROXY_OPEN_REGISTRY_KEY:
	{
		auto OpenRegInfo = (OpenCreateRegistryInfo*)UserData;
		HANDLE NewKeyHandle = NULL;

		if (DataSize < sizeof(OpenCreateRegistryInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyOpenKey(OpenRegInfo, &NewKeyHandle);

		HANDLE* Output = (HANDLE*)OutBuffer;
		*Output = NewKeyHandle;

	}
	break;

	case IOCTL_API_PROXY_DELETE_REGISTRY_KEY:
	{
		auto KeyHandle = (HANDLE*)UserData;
		Status = APIProxyDeleteRegistryKey(*KeyHandle);

	}
	break;

	case IOCTL_API_PROXY_REGISTRY_SET_KEY:
	{
		auto SetValueInfo = (RegistrySetValueInfo*)UserData;
		if (DataSize < sizeof(RegistrySetValueInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyRegistrySetValue(SetValueInfo);
	}
	break;

	case IOCTL_API_PROXY_REGISTRY_QUERY_KEY_VALUE:
	{
		auto QueryKeyValueInfo = (RegistryQueryKeyValueInfo*)UserData;
		if (DataSize < sizeof(RegistryQueryKeyValueInfo)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyRegistryQueryValue(QueryKeyValueInfo);

	}
	break;

	case IOCTL_API_PROXY_WSAStartup:
	{
		auto WSAStartInfo = (WSAStartCleanUp*)UserData;
		if (DataSize < sizeof(WSAStartCleanUp)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyWSAStartup(WSAStartInfo);

	}
	break;

	case IOCTL_API_PROXY_WSACleanup:
	{
		auto WSASCleanUpInfo = (WSAStartCleanUp*)UserData;
		if (DataSize < sizeof(WSAStartCleanUp)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyWSACleanup(WSASCleanUpInfo);

	}
	break;

	case IOCTL_API_PROXY_Socket:
	{
		auto SocketInfo = (SocketStruct*)UserData;
		if (DataSize < sizeof(SocketStruct)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxySocket(&(SocketInfo->WSAStartCleanUpptr), (PKSOCKET*)&(SocketInfo->Socket), 
			SocketInfo->Domain, SocketInfo->Type, SocketInfo->Protocol, SocketInfo->Flags);

	}
	break;

	case IOCTL_API_PROXY_CloseSocket:
	{
		auto SocketPtr = (PVOID*)UserData;
		if (DataSize < sizeof(PVOID)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyCloseSocket((PKSOCKET)*SocketPtr);

	}
	break;

	case IOCTL_API_PROXY_Connect:
	{
		auto ConnectInfo = (ConnectStruct*)UserData;
		if (DataSize < sizeof(ConnectStruct)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyConnect(ConnectInfo);
		DbgPrint("Status %x\n", Status);
	}
	break;

	case IOCTL_API_PROXY_Send:
	{
		auto SendInfo = (SendRecvStruct*)UserData;
		if (DataSize < sizeof(SendRecvStruct)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxySend(SendInfo);

	}
	break;

	case IOCTL_API_PROXY_Recv:
	{
		auto RecvInfo = (SendRecvStruct*)UserData;
		if (DataSize < sizeof(SendRecvStruct)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyRecv(RecvInfo);

	}
	break;


	case IOCTL_API_PROXY_Bind:
	{
		auto BindInfo = (BindStruct*)UserData;
		if (DataSize < sizeof(BindStruct)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyBind(BindInfo);

	}
	break;

	case IOCTL_API_PROXY_Accept:
	{
		auto AcceptInfo = (AcceptStruct*)UserData;
		if (DataSize < sizeof(AcceptStruct)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyAccept(AcceptInfo);

	}
	break;

	case IOCTL_API_PROXY_listen:
	{
		APIProxyListen();

	}
	break;

	case IOCTL_API_PROXY_GetAddrInfo:
	{
		auto AddrInfo = (GetAddrInfoStruct*)UserData;
		if (DataSize < sizeof(GetAddrInfoStruct)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}


		Status = APIProxtGetAddrInfo(AddrInfo);

	}
	break;

	case IOCTL_API_PROXY_FreeAddrInfo:
	{
		auto AddrInfo = (struct addrinfo*)UserData;
		if (DataSize < sizeof(struct addrinfo*)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		Status = APIProxyFreeAddrInfo(AddrInfo);

	}
	break;

	default:
		Status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

Finish:

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = DataWritten;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

