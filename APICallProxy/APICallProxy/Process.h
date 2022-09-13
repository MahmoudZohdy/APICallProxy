#pragma once


NTSTATUS APIProxyTerminateProcess(DWORD64* PID) {
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process;

	__try {

		Status = PsLookupProcessByProcessId((HANDLE)(*PID), &Process);

		if (!NT_SUCCESS(Status)) {
			return Status;
		}

		Status = MmUnmapViewOfSection(Process, PsGetProcessSectionBaseAddress(Process)); // Get the base address of process's executable image and unmap it

#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Terminate Process PID[%d] Status Code 0x%x\n", *PID, Status);
		}
#endif 

		ObDereferenceObject(Process); // Dereference the target process
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Terminating process Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyOpenProcess(HANDLE* PID, HANDLE* ProcessHandle) {

	NTSTATUS Status = STATUS_SUCCESS;
	CLIENT_ID ClientID;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
	Status = STATUS_UNSUCCESSFUL;

	__try {
		DWORD64 TID = APIProxyGetAnyTIDFromPID((DWORD64)(*PID));

		if (TID == 0) {
			return Status;
		}
		InitializeObjectAttributes(&objAttr,
			NULL,
			OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
		ClientID.UniqueProcess = *PID;
		ClientID.UniqueThread = (HANDLE)TID;
		Status = ZwOpenProcess(ProcessHandle, PROCESS_ALL_ACCESS, &objAttr, &ClientID);
#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Open Process Status Code 0x%x\n", Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Opening process Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxySuspendProcess(HANDLE* ProcessHandle) {
	NTSTATUS Status = STATUS_SUCCESS;
	__try {
		PEPROCESS Process;
		Status = ObReferenceObjectByHandle(*ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);
		//Status = PsLookupProcessByProcessId(*PID, &Process);
		if (NT_SUCCESS(Status)) {
			Status = PsSuspendProcess(Process);
			ObDereferenceObject(Process);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Suspend Process Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyResumeProcess(HANDLE* ProcessHandle) {
	NTSTATUS Status = STATUS_SUCCESS;
	__try {
		PEPROCESS Process;
		Status = ObReferenceObjectByHandle(*ProcessHandle, PROCESS_ALL_ACCESS, *PsProcessType, KernelMode, (PVOID*)&Process, NULL);
		//Status = PsLookupProcessByProcessId(*PID, &Process);
		if (NT_SUCCESS(Status)) {
			Status = PsResumeProcess(Process);
			ObDereferenceObject(Process);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Resume Process Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

