#pragma once


NTSTATUS APIProxyCloseHandle(HANDLE* Handle) {
	NTSTATUS Status = STATUS_SUCCESS;

	__try {
		Status = ObCloseHandle(*Handle, KernelMode);
#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error CloseHandle Status Code 0x%x\n", Status);
		}
#endif 
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while CloseHandle Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyAllocateVirtualMemory(AllocateVirtualMeomryInfo* AllocateMemoryInfo) {
	NTSTATUS Status = STATUS_SUCCESS;
	__try {
		Status = ZwAllocateVirtualMemory(AllocateMemoryInfo->ProcessHandle, &AllocateMemoryInfo->BaseAddress, 0, &AllocateMemoryInfo->RegionSize, AllocateMemoryInfo->AllocationType, AllocateMemoryInfo->Protect);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Allocation Memory inside process Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyFreeVirtualMemory(FreeVirtualMeomryInfo* FreeMemoryInfo) {
	NTSTATUS Status = STATUS_SUCCESS;
	SIZE_T RegionSize = NULL;

	__try {
		Status =  ZwFreeVirtualMemory(FreeMemoryInfo->ProcessHandle, &(FreeMemoryInfo->BaseAddress), &RegionSize, MEM_RELEASE);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Free Memory inside process Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyProtectVirtualMemory(VirtualProtectInfo* MemoryProtectionInfo) {
	NTSTATUS Status = STATUS_SUCCESS;

	__try {
		Status = ZwProtectVirtualMemory(MemoryProtectionInfo->ProcessHandle, &MemoryProtectionInfo->BaseAddress, &MemoryProtectionInfo->NumberOfBytesToProtect, MemoryProtectionInfo->NewAccessProtection, &MemoryProtectionInfo->OldAccessProtection);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Changing Memory Protection Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyReadVirtualMemory(ReadWriteVirtualMemoryInfo* ReadMemoryInfo) {
	NTSTATUS Status = STATUS_SUCCESS;

	PEPROCESS Process = NULL;

	Status = ObReferenceObjectByHandle(ReadMemoryInfo->ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("APICallProxy: Error Refrence process using ObReferenceObjectByHandle Failed Status Code %x\n", Status);
		return Status;
	}

	__try {

		// TODO there is crash if the address in not valid
		SIZE_T Result;
		Status = MmCopyVirtualMemory(Process, ReadMemoryInfo->BaseAddress, PsGetCurrentProcess(), ReadMemoryInfo->Data, ReadMemoryInfo->DataLen, KernelMode, &Result);
#if DEBUG
		if (!NT_SUCCESS(Status))
			DbgPrint("APICallProxy: Error Reading Virtual Address Space using MmCopyVirtualMemory  Failed Status Code %x  %x\n", Status, Result);
#endif

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Allocation Memory inside process Status Code 0x%x\n", Status);
#endif

	}

	ObDereferenceObject(Process); // Dereference the target process

	return Status;
}

NTSTATUS APIProxyWriteVirtualMemory(_In_ ReadWriteVirtualMemoryInfo* WriteMemoryInfo) {
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = ObReferenceObjectByHandle(WriteMemoryInfo->ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	__try {

		SIZE_T Result;
		Status = MmCopyVirtualMemory(PsGetCurrentProcess(), WriteMemoryInfo->Data, Process, WriteMemoryInfo->BaseAddress, WriteMemoryInfo->DataLen, KernelMode, &Result);

#if DEBUG
		if (!NT_SUCCESS(Status))
			DbgPrint("APICallProxy: Error Writting Virtual Address Space using MmCopyVirtualMemory  Failed Status Code %x\n", Status);
#endif

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Allocation Memory inside process Status Code 0x%x\n", Status);
#endif

	}

	ObDereferenceObject(Process); // Dereference the target process

	return Status;
}

NTSTATUS APIProxyQuerySystemInformation(ULONG InformationClass, PVOID InformationData, ULONG* DataSize) {

	ULONG bufferSize = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	__try {

		Status = ZwQuerySystemInformation(InformationClass, InformationData, *DataSize, &bufferSize);
		if (Status == STATUS_INFO_LENGTH_MISMATCH) {
#if DEBUG
			DbgPrint("APICallProxy: Error Get System information Status Code 0x%x\n", Status);
#endif 
			Status = STATUS_BUFFER_TOO_SMALL;
			*DataSize = bufferSize;
		}

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Query System information Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyCreateSection(CreateSectionInfo* SectionInfo, HANDLE* SectionHandle) {
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
	UNICODE_STRING uniName;
	__try {
		RtlInitUnicodeString(&uniName, SectionInfo->SectionName);

		InitializeObjectAttributes(&objAttr, &uniName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		Status = ZwCreateSection(SectionHandle, SectionInfo->DesiredAccess, &objAttr, &SectionInfo->SectionMaxSize, SectionInfo->SectionPageProtection, SectionInfo->AllocationAttribute, SectionInfo->FileHandle);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Create Section Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyOpenSection(OpenSectionInfo* SectionInfo, HANDLE* SectionHandle) {
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
	UNICODE_STRING uniName;

	__try {

		RtlInitUnicodeString(&uniName, SectionInfo->SectionName);

		InitializeObjectAttributes(&objAttr, &uniName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		Status = ZwOpenSection(SectionHandle, SectionInfo->DesiredAccess, &objAttr);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Open Section Status Code 0x%x\n", Status);
#endif

	}

	return Status;
}

NTSTATUS APIProxyMapViewOfSection(MapViewOfSectionInfo* MapInfo) {
	NTSTATUS Status = STATUS_SUCCESS;

	__try {
		Status = ZwMapViewOfSection(MapInfo->SectionHandle, MapInfo->ProcessHandle, &MapInfo->BaseAddress, 0, MapInfo->CommetSize, 0, &MapInfo->SizeOfView, ViewUnmap, 0, MapInfo->Win32Protect);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Map View Of Section Status Code 0x%x\n", Status);
#endif

	}

	return Status;
}

NTSTATUS APIProxyUnMapViewOfSection(UNMapViewOfSectionInfo* UnMapInfo) {
	NTSTATUS Status = STATUS_SUCCESS;

	__try {
		Status = ZwUnmapViewOfSection(UnMapInfo->ProcessHandle, UnMapInfo->BaseAddress);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while UnMap View Of Section Status Code 0x%x\n", Status);
#endif

	}

	return Status;
}

NTSTATUS APIProxyQueueUserAPC(QueueUSerApcInfo* APCInfo) {
	NTSTATUS Status = STATUS_SUCCESS;
	PRKAPC UserAPC, AlertAPC;

	__try {

		UserAPC = (PRKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
		if (!UserAPC) {
			Status = STATUS_INSUFFICIENT_RESOURCES;
			return Status;
		}

		AlertAPC = (PRKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
		if (!AlertAPC) {
			ExFreePool(UserAPC);
			Status = STATUS_INSUFFICIENT_RESOURCES;
			return Status;
		}

		PETHREAD PeThread;
		Status = ObReferenceObjectByHandle(APCInfo->ThreadHandle, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&PeThread, NULL);
		if (!NT_SUCCESS(Status)) {
			ExFreePool(UserAPC);
			ExFreePool(AlertAPC);
			return Status;
		}

		//used to execute code in user-mode
		KeInitializeApc(UserAPC, (PKTHREAD)PeThread, OriginalApcEnvironment, APIProxyApcKernelRoutine,
			NULL, (PKNORMAL_ROUTINE)APCInfo->ProcAddres, UserMode, APCInfo->ArgumentData);

		//used to make the thread in alertable state
		KeInitializeApc(AlertAPC, (PKTHREAD)PeThread, OriginalApcEnvironment, APIProxyApcAlertThread,
			NULL, NULL, KernelMode, NULL);

		if (KeInsertQueueApc(UserAPC, NULL, NULL, 0)) {
			if (KeInsertQueueApc(AlertAPC, NULL, NULL, 0)) {
				Status = PsIsThreadTerminating(PeThread) ? STATUS_THREAD_IS_TERMINATING : STATUS_SUCCESS;
			}
			else {
				Status = STATUS_UNSUCCESSFUL;
				ExFreePool(AlertAPC);
			}
		}
		else {
			Status = STATUS_UNSUCCESSFUL;
			ExFreePool(UserAPC);
			ExFreePool(AlertAPC);
		}


		ObDereferenceObject(PeThread);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Queuing APC Status Code 0x%x\n", Status);
#endif

	}

	return Status;
}


NTSTATUS APIProxyLoadDriver(PUNICODE_STRING DriverRegistryPath) {
	NTSTATUS Status = STATUS_SUCCESS;

	__try {
		Status = ZwLoadDriver(DriverRegistryPath);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Loading Driver Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyUnLoadDriver(PUNICODE_STRING DriverRegistryPath) {
	NTSTATUS Status = STATUS_SUCCESS;

	__try {
		Status = ZwUnloadDriver(DriverRegistryPath);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Loading Driver Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

