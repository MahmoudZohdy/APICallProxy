#pragma once


NTSTATUS APIProxyCreateFile(CreateFileInfo* FileInfo, HANDLE* FileHandle) {
	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING uniName;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
	IO_STATUS_BLOCK ioStatusBlock;

	__try {
		RtlInitUnicodeString(&uniName, FileInfo->FileName);

		InitializeObjectAttributes(&objAttr, &uniName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		//Map the user creation option to kernel flags
#define  CREATE_ALWAYS  2 
#define  CREATE_NEW		1
#define  OPEN_ALWAYS	4 
#define  OPEN_EXISTING  3

		ULONG CreateOption = FILE_CREATE;
		switch (FileInfo->CreateDisposition)
		{
		case CREATE_ALWAYS:
			CreateOption = FILE_SUPERSEDE;
			break;
		case CREATE_NEW:
			CreateOption = FILE_CREATE;
			break;
		case OPEN_ALWAYS:
			CreateOption = FILE_OPEN_IF;
			break;
		case OPEN_EXISTING:
			CreateOption = FILE_OPEN;
			break;
		default:
			break;
		}

		Status = ZwCreateFile(FileHandle, FileInfo->DesiredAccess,
			&objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
			FileInfo->ShareAccess, CreateOption, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Create File %wZ Status Code 0x%x\n", uniName, Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Creating File Status Code 0x%x\n", Status);
#endif

	}

	return Status;
}

NTSTATUS APIProxyOpenFile(CreateFileInfo* FileInfo, HANDLE* FileHandle) {

	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING uniName;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
	IO_STATUS_BLOCK ioStatusBlock;

	__try {
		RtlInitUnicodeString(&uniName, FileInfo->FileName);

		InitializeObjectAttributes(&objAttr, &uniName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		Status = ZwOpenFile(FileHandle, FileInfo->DesiredAccess, &objAttr, &ioStatusBlock, FileInfo->ShareAccess, FILE_SYNCHRONOUS_IO_NONALERT);
#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Open File %wZ Status Code 0x%x\n", uniName, Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Opening File Status Code 0x%x\n", Status);

#endif

	}
	return Status;
}

NTSTATUS APIProxyDeleteFile(WCHAR* FileName) {

	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING uniName;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };

	__try {
		RtlInitUnicodeString(&uniName, FileName);

		InitializeObjectAttributes(&objAttr, &uniName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		Status = ZwDeleteFile(&objAttr);
#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Delete File %wZ Status Code 0x%x\n", uniName, Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Deleting File Status Code 0x%x\n", Status);
#endif

	}

	return Status;
}

NTSTATUS APIProxyWriteFile(ReadWriteData* WriteInfo) {
	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK ioStatusBlock;

	__try {
		Status = ZwWriteFile(WriteInfo->FileHandle, NULL, NULL, NULL, &ioStatusBlock, WriteInfo->Data, WriteInfo->DataLen, &(WriteInfo->ByteOffset), NULL);
#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Write Data to file Status Code 0x%x\n", Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Writing data to File Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyReadFile(ReadWriteData* ReadInfo) {
	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK ioStatusBlock;

	__try {
		Status = ZwReadFile(ReadInfo->FileHandle, NULL, NULL, NULL, &ioStatusBlock, ReadInfo->Data, ReadInfo->DataLen, &(ReadInfo->ByteOffset), NULL);
#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: ErrorRead Data From File Status Code 0x%x\n", Status);
		}
#endif 
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Reading Data From File Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyGetFileSize(HANDLE* FileHandle, FILE_STANDARD_INFORMATION* FileInfo) {
	NTSTATUS Status = STATUS_SUCCESS;
	IO_STATUS_BLOCK ioStatusBlock;

	__try {
		Status = ZwQueryInformationFile(*FileHandle, &ioStatusBlock, FileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error While Geeting File size Status Code 0x%x\n", Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Getting File Size tatus Code 0x%x\n", Status);
#endif

	}
	return Status;
}
