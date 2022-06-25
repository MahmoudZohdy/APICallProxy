#pragma once


DWORD64  APIProxyGetPIDFromProcessName(_In_ WCHAR* ProcessName) {
	DWORD64 PID = 0;
	PSYSTEM_PROCESSES ProcessInfo = NULL;
	ULONG DataSize = 0;
	__try {
		NTSTATUS Status = APIProxyQuerySystemInformation(SystemProcessInformation, ProcessInfo, &DataSize);
		if (Status == STATUS_BUFFER_TOO_SMALL) {

			ProcessInfo = (PSYSTEM_PROCESSES)ExAllocatePool(PagedPool, DataSize);

			if (ProcessInfo) {
				Status = APIProxyQuerySystemInformation(SystemProcessInformation, ProcessInfo, &DataSize);
				if (!NT_SUCCESS(Status)) {
#if DEBUG
					DbgPrint("APICallProxy: Error Get PID From Process Name Status Code 0x%x\n", Status);
#endif 
					ExFreePool(ProcessInfo);
					return PID;
				}
			}
			else {
#if DEBUG
				DbgPrint("APICallProxy: Error Get PID From Process Name Can't allocate Memory Status Code 0x%x\n", Status);
#endif 
				return PID;
			}
		}
		else if (!NT_SUCCESS(Status)) {
#if DEBUG
			DbgPrint("APICallProxy: Error Get PID From Process Name Status Code 0x%x\n", Status);
#endif 
			return PID;
		}

		PVOID Memory = ProcessInfo;

		do {
			if (ProcessInfo->ProcessName.Length) {
				auto ProcessExist = wcsstr(ProcessInfo->ProcessName.Buffer, ProcessName);
				if (ProcessExist) {
					PID = ProcessInfo->ProcessId;
					break;
				}
			}
			ProcessInfo = (PSYSTEM_PROCESSES)((unsigned char*)ProcessInfo + ProcessInfo->NextEntryDelta);
		} while (ProcessInfo->NextEntryDelta);

		ExFreePool(Memory);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

#if DEBUG	
		DbgPrint("APICallProxy: Error Access Violation while Getting the PID from process name\n");
#endif

	}
	return PID;
}

DWORD64  APIProxyGetAnyTIDFromPID(_In_ DWORD64 PID) {
	DWORD64 TID = 0;

	PSYSTEM_PROCESSES ProcessInfo = NULL;
	ULONG DataSize = 0;
	NTSTATUS Status = APIProxyQuerySystemInformation(SystemProcessInformation, ProcessInfo, &DataSize);
	if (Status == STATUS_BUFFER_TOO_SMALL) {
		ProcessInfo = (PSYSTEM_PROCESSES)ExAllocatePool(PagedPool, DataSize);

		if (ProcessInfo) {
			Status = APIProxyQuerySystemInformation(SystemProcessInformation, ProcessInfo, &DataSize);
			if (!NT_SUCCESS(Status)) {
				//Error Happend
				ExFreePool(ProcessInfo);
				return TID;
			}
		}
	}
	else if (!NT_SUCCESS(Status)) {
		//Error Happend
		return TID;
	}

	PVOID Memory = ProcessInfo;

	do {
		if (ProcessInfo->ProcessId == PID) {
			PSYSTEM_THREADS  pSysThread = ProcessInfo->Threads;
			TID = (DWORD64)pSysThread->ClientId.UniqueThread;
			break;
		}
		ProcessInfo = (PSYSTEM_PROCESSES)((unsigned char*)ProcessInfo + ProcessInfo->NextEntryDelta);
	} while (ProcessInfo->NextEntryDelta);

	ExFreePool(Memory);
	return TID;
}

VOID  APIProxyApcKernelRoutine(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine, _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2) {
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//free the allocate KAPC Struct
	ExFreePool(Apc);
}

VOID  APIProxyApcAlertThread(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine, _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2) {
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//free the allocate KAPC Struct
	KeTestAlertThread(UserMode);
	ExFreePool(Apc);
}

