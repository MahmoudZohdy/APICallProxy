#pragma once

NTSTATUS APIProxyOpenThread(HANDLE* TID, HANDLE* ThreadHandle) {
	CLIENT_ID ClientID;
	OBJECT_ATTRIBUTES objAttr = { sizeof(OBJECT_ATTRIBUTES) };
	NTSTATUS Status = STATUS_SUCCESS;

	__try {
		InitializeObjectAttributes(&objAttr,
			NULL,
			OBJ_KERNEL_HANDLE,
			NULL,
			NULL);
		ClientID.UniqueProcess = 0;
		ClientID.UniqueThread = *TID;
		Status = ZwOpenThread(ThreadHandle, PROCESS_ALL_ACCESS, &objAttr, &ClientID);
#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Open Thread Status Code 0x%x\n", Status);
		}
#endif 
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Opening Thread Status Code 0x%x\n", Status);
#endif

	}
	return Status;
}

NTSTATUS APIProxyGetThreadContext(ThreadContextInfo* ThreadInfo) {
	NTSTATUS Status = STATUS_SUCCESS;

	PETHREAD pThread;
	Status = PsLookupThreadByThreadId((HANDLE)ThreadInfo->ThreadID, &pThread);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	Status = PsGetContextThread(pThread, &ThreadInfo->ThreadContext, UserMode);
	ObDereferenceObject(pThread);

	return Status;
}

NTSTATUS APIProxySetThreadContext(ThreadContextInfo* ThreadInfo) {
	NTSTATUS Status = STATUS_SUCCESS;

	PETHREAD pThread;
	Status = PsLookupThreadByThreadId((HANDLE)ThreadInfo->ThreadID, &pThread);
	if (!NT_SUCCESS(Status)) {
		return Status;
	}
	Status = PsSetContextThread(pThread, &ThreadInfo->ThreadContext, UserMode);
	ObDereferenceObject(pThread);

	return Status;
}