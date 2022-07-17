#pragma once


DWORD64 APIProxyGetPIDFromProcessName(_In_ WCHAR* ProcessName) {
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

DWORD64 APIProxyGetAnyTIDFromPID(_In_ DWORD64 PID) {
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

VOID APIProxyApcKernelRoutine(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine, _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2) {
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//free the allocate KAPC Struct
	ExFreePool(Apc);
}

VOID APIProxyApcAlertThread(_In_ PKAPC Apc, _Inout_ PKNORMAL_ROUTINE* NormalRoutine, _Inout_ PVOID* NormalContext, _Inout_ PVOID* SystemArgument1, _Inout_ PVOID* SystemArgument2) {
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//free the allocate KAPC Struct
	KeTestAlertThread(UserMode);
	ExFreePool(Apc);
}


///Network Utility

DWORD32 APIProxyhtonl(DWORD32 hostlong) {
    return RtlUlongByteSwap(hostlong);
}

unsigned short APIProxyhtons(unsigned short hostshort) {
    return RtlUshortByteSwap(hostshort);
}

DWORD32 APIProxyntohl(DWORD32 netlong) {
    return RtlUlongByteSwap(netlong);
}

unsigned short APIProxyntohs(unsigned short netshort) {
    return RtlUshortByteSwap(netshort);
}


NTSTATUS APIProxyAsyncContextCompletionRoutine(
    _In_ PDEVICE_OBJECT	DeviceObject,
    _In_ PIRP Irp,
    _In_ PKEVENT CompletionEvent
) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);

    KeSetEvent(CompletionEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS APIProxyAsyncContextAllocate(_Out_ PKSOCKET_ASYNC_CONTEXT AsyncContext) {

    KeInitializeEvent(
        &AsyncContext->CompletionEvent,
        SynchronizationEvent,
        FALSE
    );

    AsyncContext->Irp = IoAllocateIrp(1, FALSE);

    if (AsyncContext->Irp == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // KspAsyncContextCompletionRoutine will set
    // the CompletionEvent.
    IoSetCompletionRoutine(
        AsyncContext->Irp,
        (PIO_COMPLETION_ROUTINE)&APIProxyAsyncContextCompletionRoutine,
        &AsyncContext->CompletionEvent,
        TRUE,
        TRUE,
        TRUE
    );

    return STATUS_SUCCESS;
}

VOID APIProxyAsyncContextFree(_In_ PKSOCKET_ASYNC_CONTEXT AsyncContext) {
    // Free the IRP.
    IoFreeIrp(AsyncContext->Irp);
}

VOID APIProxyAsyncContextReset(_In_ PKSOCKET_ASYNC_CONTEXT AsyncContext) {

    KeResetEvent(&AsyncContext->CompletionEvent);

    IoReuseIrp(AsyncContext->Irp, STATUS_UNSUCCESSFUL);

    IoSetCompletionRoutine(
        AsyncContext->Irp,
        (PIO_COMPLETION_ROUTINE)&APIProxyAsyncContextCompletionRoutine,
        &AsyncContext->CompletionEvent,
        TRUE,
        TRUE,
        TRUE
    );
}


NTSTATUS APIProxyAsyncContextWaitForCompletion(
    _In_ PKSOCKET_ASYNC_CONTEXT AsyncContext,
    _Inout_ PNTSTATUS Status
) {
    if (*Status == STATUS_PENDING) {
        KeWaitForSingleObject(
            &AsyncContext->CompletionEvent,
            Executive,
            KernelMode,
            FALSE,
            NULL
        );

        *Status = AsyncContext->Irp->IoStatus.Status;
    }

    return *Status;
}


NTSTATUS APIProxyAddrInfoToAddrInfoEx(
    _In_ PADDRINFOA AddrInfo,
    _Out_ PADDRINFOEXW* AddrInfoEx
) {
    NTSTATUS Status;

    if (AddrInfo == NULL) {
        *AddrInfoEx = NULL;
        return STATUS_SUCCESS;
    }

    PADDRINFOEXW Result = (PADDRINFOEXW)ExAllocatePoolWithTag(PagedPool, sizeof(ADDRINFOEXW), MEMORY_TAG);

    if (Result == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Error1;
    }

    RtlZeroMemory(Result, sizeof(ADDRINFOEXW));
    Result->ai_flags = AddrInfo->ai_flags;
    Result->ai_family = AddrInfo->ai_family;
    Result->ai_socktype = AddrInfo->ai_socktype;
    Result->ai_protocol = AddrInfo->ai_protocol;
    Result->ai_addrlen = AddrInfo->ai_addrlen;


    ANSI_STRING CanonicalNameAnsi;
    UNICODE_STRING CanonicalNameUnicode;

    CanonicalNameAnsi.Buffer = NULL;

    if (AddrInfo->ai_canonname) {
        RtlInitAnsiString(&CanonicalNameAnsi, AddrInfo->ai_canonname);

        Status = RtlAnsiStringToUnicodeString(&CanonicalNameUnicode, &CanonicalNameAnsi, TRUE);

        if (!NT_SUCCESS(Status)) {
            goto Error2;
        }

        Result->ai_canonname = CanonicalNameUnicode.Buffer;
    }

    Result->ai_addr = AddrInfo->ai_addr;

    PADDRINFOEXW NextAddrInfo;
    Status = APIProxyAddrInfoToAddrInfoEx(AddrInfo->ai_next, &NextAddrInfo);

    if (!NT_SUCCESS(Status)) {
        goto Error3;
    }

    Result->ai_next = NextAddrInfo;

    *AddrInfoEx = Result;

    return Status;

Error3:
    if (CanonicalNameAnsi.Buffer != NULL) {
        RtlFreeAnsiString(&CanonicalNameAnsi);
    }
Error2:
    ExFreePoolWithTag(Result, MEMORY_TAG);

Error1:
    return Status;
}

NTSTATUS APIProxyAddrInfoExToAddrInfo(
    _In_ PADDRINFOEXW AddrInfoEx,
    _Out_ PADDRINFOA* AddrInfo
) {

    NTSTATUS Status;

    // Convert NULL input into NULL output.
    if (AddrInfoEx == NULL) {
        *AddrInfo = NULL;
        return STATUS_SUCCESS;
    }

    // Allocate memory for the output structure.
    PADDRINFOA Result = (PADDRINFOA)ExAllocatePoolWithTag(PagedPool, sizeof(ADDRINFOA), MEMORY_TAG);

    if (Result == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Error1;
    }

    // Copy numeric values.
    RtlZeroMemory(Result, sizeof(ADDRINFOA));
    Result->ai_flags = AddrInfoEx->ai_flags;
    Result->ai_family = AddrInfoEx->ai_family;
    Result->ai_socktype = AddrInfoEx->ai_socktype;
    Result->ai_protocol = AddrInfoEx->ai_protocol;
    Result->ai_addrlen = AddrInfoEx->ai_addrlen;

    // Copy canonical name.
    UNICODE_STRING CanonicalNameUnicode;
    ANSI_STRING CanonicalNameAnsi;

    CanonicalNameAnsi.Buffer = NULL;

    if (AddrInfoEx->ai_canonname) {
        RtlInitUnicodeString(&CanonicalNameUnicode, AddrInfoEx->ai_canonname);
        Status = RtlUnicodeStringToAnsiString(&CanonicalNameAnsi, &CanonicalNameUnicode, TRUE);

        if (!NT_SUCCESS(Status)) {
            goto Error2;
        }

        Result->ai_canonname = CanonicalNameAnsi.Buffer;
    }

    // Copy address.
    Result->ai_addr = AddrInfoEx->ai_addr;

    // Copy the next structure (recursively).
    PADDRINFOA NextAddrInfo;
    Status = APIProxyAddrInfoExToAddrInfo(AddrInfoEx->ai_next, &NextAddrInfo);

    if (!NT_SUCCESS(Status)) {
        goto Error3;
    }

    Result->ai_next = NextAddrInfo;


    *AddrInfo = Result;

    return Status;

Error3:
    if (CanonicalNameAnsi.Buffer != NULL) {
        RtlFreeAnsiString(&CanonicalNameAnsi);
    }

Error2:
    ExFreePoolWithTag(Result, MEMORY_TAG);

Error1:
    return Status;
}

VOID APIProxyFreeAddrInfoUtility(_In_ PADDRINFOA AddrInfo) {

    // Free all structures recursively.
    if (AddrInfo->ai_next) {
        APIProxyFreeAddrInfoUtility(AddrInfo->ai_next);
    }

    // Free the canonical name buffer.
    if (AddrInfo->ai_canonname) {
        ANSI_STRING CanonicalName;
        RtlInitAnsiString(&CanonicalName, AddrInfo->ai_canonname);
        RtlFreeAnsiString(&CanonicalName);
    }

    // Finally, free the structure itself.
    ExFreePoolWithTag(AddrInfo, MEMORY_TAG);
}

VOID APIProxyFreeAddrInfoEx(_In_ PADDRINFOEXW AddrInfo) {

    // Free all structures recursively.
    if (AddrInfo->ai_next) {
        APIProxyFreeAddrInfoEx(AddrInfo->ai_next);
    }

    // Free the canonical name buffer.
    if (AddrInfo->ai_canonname) {
        UNICODE_STRING CanonicalName;
        RtlInitUnicodeString(&CanonicalName, AddrInfo->ai_canonname);
        RtlFreeUnicodeString(&CanonicalName);
    }

    // Finally, free the structure itself.
    ExFreePoolWithTag(AddrInfo, MEMORY_TAG);
}


NTSTATUS KsGetAddrInfo(
    WSAStartCleanUp* WSAInfo,
    _In_ PUNICODE_STRING NodeName,
    _In_ PUNICODE_STRING ServiceName,
    _In_ PADDRINFOEXW Hints,
    _Out_ PADDRINFOEXW* Result
) {
    NTSTATUS Status;
    PWSK_PROVIDER_NPI WskProvider = (PWSK_PROVIDER_NPI)WSAInfo->WskProviderPtr;

    KSOCKET_ASYNC_CONTEXT AsyncContext;
    Status = APIProxyAsyncContextAllocate(&AsyncContext);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = WskProvider->Dispatch->WskGetAddressInfo(
        WskProvider->Client,         // Client
        NodeName,                   // NodeName
        ServiceName,                // ServiceName
        0,                          // NameSpace
        NULL,                       // Provider
        Hints,                      // Hints
        Result,                     // Result
        NULL,                       // OwningProcess
        NULL,                       // OwningThread
        AsyncContext.Irp            // Irp
    );

    APIProxyAsyncContextWaitForCompletion(&AsyncContext, &Status);

    APIProxyAsyncContextFree(&AsyncContext);

    return Status;
}

VOID KsFreeAddrInfo(
    WSAStartCleanUp* WSAInfo,
    _In_ PADDRINFOEXW AddrInfo
) {
    PWSK_PROVIDER_NPI WskProvider = (PWSK_PROVIDER_NPI)WSAInfo->WskProviderPtr;
    WskProvider->Dispatch->WskFreeAddressInfo(
        WskProvider->Client,         // Client
        AddrInfo                    // AddrInfo
    );
}

NTSTATUS KsCreateSocket(
    WSAStartCleanUp* WSAInfo,
    _Out_ PKSOCKET* Socket,
    _In_ ADDRESS_FAMILY AddressFamily,
    _In_ USHORT SocketType,
    _In_ ULONG Protocol,
    _In_ ULONG Flags
) {
    PWSK_PROVIDER_NPI WskProvider = (PWSK_PROVIDER_NPI)WSAInfo->WskProviderPtr;
    NTSTATUS Status;


    PKSOCKET NewSocket = (PKSOCKET)ExAllocatePoolWithTag(PagedPool, sizeof(KSOCKET), MEMORY_TAG);

    if (!NewSocket) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = APIProxyAsyncContextAllocate(&NewSocket->AsyncContext);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Create the WSK socket.
    Status = WskProvider->Dispatch->WskSocket(
        WskProvider->Client,         // Client
        AddressFamily,              // AddressFamily
        SocketType,                 // SocketType
        Protocol,                   // Protocol
        Flags,                      // Flags
        NULL,                       // SocketContext
        NULL,                       // Dispatch
        NULL,                       // OwningProcess
        NULL,                       // OwningThread
        NULL,                       // SecurityDescriptor
        NewSocket->AsyncContext.Irp // Irp
    );

    APIProxyAsyncContextWaitForCompletion(&NewSocket->AsyncContext, &Status);

    // Save the socket instance and the socket dispatch table.
    if (NT_SUCCESS(Status)) {
        NewSocket->WskSocket = (PWSK_SOCKET)NewSocket->AsyncContext.Irp->IoStatus.Information;
        NewSocket->WskDispatch = (PVOID)NewSocket->WskSocket->Dispatch;

        *Socket = NewSocket;
    }

    return Status;
}


NTSTATUS KsCloseSocket(_In_ PKSOCKET Socket) {
    NTSTATUS Status;

    APIProxyAsyncContextReset(&Socket->AsyncContext);

    Status = Socket->WskConnectionDispatch->Basic.WskCloseSocket(
        Socket->WskSocket,
        Socket->AsyncContext.Irp
    );

    APIProxyAsyncContextWaitForCompletion(&Socket->AsyncContext, &Status);

    APIProxyAsyncContextFree(&Socket->AsyncContext);

    ExFreePoolWithTag(Socket, MEMORY_TAG);

    return Status;
}


//TODO: Make the Bind work for all type of socket
NTSTATUS KsBind(_In_ PKSOCKET Socket, _In_ PSOCKADDR LocalAddress) {
    NTSTATUS Status;

    APIProxyAsyncContextReset(&Socket->AsyncContext);

    // Bind the socket.
    Status = Socket->WskListenDispatch->WskBind(
        Socket->WskSocket,          // Socket
        LocalAddress,               // LocalAddress
        0,                          // Flags (reserved)
        Socket->AsyncContext.Irp    // Irp
    );

    APIProxyAsyncContextWaitForCompletion(&Socket->AsyncContext, &Status);

    return Status;
}

NTSTATUS KsAccept(
    _In_ PKSOCKET Socket,
    _Out_ PKSOCKET* NewSocket,
    _Out_opt_ PSOCKADDR LocalAddress,
    _Out_opt_ PSOCKADDR RemoteAddress) {

    NTSTATUS Status;

    // Reset the async context.
    APIProxyAsyncContextReset(&Socket->AsyncContext);

    // Accept the connection.
    Status = Socket->WskListenDispatch->WskAccept(
        Socket->WskSocket,          // ListenSocket
        0,                          // Flags
        NULL,                       // AcceptSocketContext
        NULL,                       // AcceptSocketDispatch
        LocalAddress,               // LocalAddress
        RemoteAddress,              // RemoteAddress
        Socket->AsyncContext.Irp    // Irp
    );

    APIProxyAsyncContextWaitForCompletion(&Socket->AsyncContext, &Status);

    // Save the socket instance and the socket dispatch table.
    if (NT_SUCCESS(Status)) {
        PKSOCKET KNewSocket = (PKSOCKET)ExAllocatePoolWithTag(PagedPool, sizeof(KSOCKET), MEMORY_TAG);

        if (!KNewSocket) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KNewSocket->WskSocket = (PWSK_SOCKET)Socket->AsyncContext.Irp->IoStatus.Information;
        KNewSocket->WskDispatch = (PVOID)KNewSocket->WskSocket->Dispatch;
        APIProxyAsyncContextAllocate(&KNewSocket->AsyncContext);

        *NewSocket = KNewSocket;
    }

    return Status;
}

NTSTATUS KsConnect(_In_ PKSOCKET Socket, _In_ PSOCKADDR RemoteAddress) {
    NTSTATUS Status;

    // Reset the async context.
    APIProxyAsyncContextReset(&Socket->AsyncContext);

    // Bind the socket to the local address.
    SOCKADDR_IN LocalAddress;
    LocalAddress.sin_family = AF_INET;
    LocalAddress.sin_addr.s_addr = INADDR_ANY;
    LocalAddress.sin_port = 0;

    Status = Socket->WskConnectionDispatch->WskBind(
        Socket->WskSocket,          // Socket
        (PSOCKADDR)&LocalAddress,   // LocalAddress
        0,                          // Flags (reserved)
        Socket->AsyncContext.Irp    // Irp
    );

    APIProxyAsyncContextWaitForCompletion(&Socket->AsyncContext, &Status);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    // Reset the async context (again).
    APIProxyAsyncContextReset(&Socket->AsyncContext);

    // Connect to the remote host.
    // N.B.: Instead of calling WskSocket(), WskBind() and WskConnect(),
    // it is possible to just call WskSocketConnect().
    Status = Socket->WskConnectionDispatch->WskConnect(
        Socket->WskSocket,          // Socket
        RemoteAddress,              // RemoteAddress
        0,                          // Flags (reserved)
        Socket->AsyncContext.Irp    // Irp
    );

    APIProxyAsyncContextWaitForCompletion(&Socket->AsyncContext, &Status);

    return Status;
}

NTSTATUS KsSendRecv(
    _In_ PKSOCKET Socket,
    _In_ PVOID Buffer,
    _Inout_ PULONG Length,
    _In_ ULONG Flags,
    _In_ BOOLEAN Send
) {
    NTSTATUS Status;

    // Wrap the buffer into the "WSK buffer".
    WSK_BUF WskBuffer;
    WskBuffer.Offset = 0;
    WskBuffer.Length = *Length;
    WskBuffer.Mdl = IoAllocateMdl(Buffer, (ULONG)WskBuffer.Length, FALSE, FALSE, NULL);

    __try {
        MmProbeAndLockPages(WskBuffer.Mdl, KernelMode, IoWriteAccess);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Status = STATUS_ACCESS_VIOLATION;
        goto Error;
    }

    // Reset the async context.
    APIProxyAsyncContextReset(&Socket->AsyncContext);

    // Send / receive the data.
    if (Send) {
        Status = Socket->WskConnectionDispatch->WskSend(
            Socket->WskSocket,        // Socket
            &WskBuffer,               // Buffer
            Flags,                    // Flags
            Socket->AsyncContext.Irp  // Irp
        );
    }
    else {
        Status = Socket->WskConnectionDispatch->WskReceive(
            Socket->WskSocket,        // Socket
            &WskBuffer,               // Buffer
            Flags,                    // Flags
            Socket->AsyncContext.Irp  // Irp
        );
    }

    APIProxyAsyncContextWaitForCompletion(&Socket->AsyncContext, &Status);

    // Set the number of bytes sent / received.
    if (NT_SUCCESS(Status)) {
        *Length = (ULONG)Socket->AsyncContext.Irp->IoStatus.Information;
    }

    // Free the MDL.
    MmUnlockPages(WskBuffer.Mdl);

Error:
    IoFreeMdl(WskBuffer.Mdl);

    return Status;
}


NTSTATUS KsSend(
    _In_ PKSOCKET Socket,
    _In_ PVOID Buffer,
    _Inout_ PULONG Length,
    _In_ ULONG Flags
) {
    return KsSendRecv(Socket, Buffer, Length, Flags, TRUE);
}

NTSTATUS KsRecv(
    _In_ PKSOCKET Socket,
    _In_ PVOID Buffer,
    _Inout_ PULONG Length,
    _In_ ULONG Flags
) {
    return KsSendRecv(Socket, Buffer, Length, Flags, FALSE);
}