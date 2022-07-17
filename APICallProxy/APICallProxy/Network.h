#pragma once


NTSTATUS  APIProxyWSAStartup(OUT WSAStartCleanUp* WSASInfo) {
    UNREFERENCED_PARAMETER(WSASInfo);
    NTSTATUS Status = STATUS_UNSUCCESSFUL;
    WSK_CLIENT_NPI WskClient;



    PWSK_REGISTRATION WskRegistration = (PWSK_REGISTRATION)ExAllocatePoolWithTag(PagedPool, sizeof(WSK_REGISTRATION), MEMORY_TAG);
    PWSK_PROVIDER_NPI WskProvider = (PWSK_PROVIDER_NPI)ExAllocatePoolWithTag(PagedPool, sizeof(WSK_PROVIDER_NPI), MEMORY_TAG);
    PWSK_CLIENT_DISPATCH WskDispatch = (PWSK_CLIENT_DISPATCH)ExAllocatePoolWithTag(PagedPool, sizeof(WSK_CLIENT_DISPATCH), MEMORY_TAG);
    if (!WskRegistration || !WskProvider || !WskDispatch) {
        return STATUS_NO_MEMORY;
    }

    WskDispatch->Version = MAKE_WSK_VERSION(1, 0);
    WskDispatch->Reserved = 0;
    WskDispatch->WskClientEvent = NULL;

    WSASInfo->WskDispatchPtr = WskDispatch;
    WSASInfo->WskProviderPtr = WskProvider;
    WSASInfo->WskRegistrationPtr = WskRegistration;

    WskClient.ClientContext = NULL;
    WskClient.Dispatch = WskDispatch;

    Status = WskRegister(&WskClient, WskRegistration);

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = WskCaptureProviderNPI(WskRegistration, WSK_INFINITE_WAIT, WskProvider);

    return Status;
}

NTSTATUS APIProxyWSACleanup(_In_ WSAStartCleanUp* WSASInfo) {

    WskReleaseProviderNPI((PWSK_REGISTRATION)WSASInfo->WskRegistrationPtr);
    WskDeregister((PWSK_REGISTRATION)WSASInfo->WskRegistrationPtr);

    return STATUS_SUCCESS;
}

NTSTATUS APIProxtGetAddrInfo(GetAddrInfoStruct* AddrInfo) {
    NTSTATUS Status;

    // Convert node name to the UNICODE_STRING (if present).
    ANSI_STRING NodeNameAnsi;
    UNICODE_STRING NodeNameUnicode;
    PUNICODE_STRING NodeName = NULL;

    if (AddrInfo->Node) {
        RtlInitAnsiString(&NodeNameAnsi, AddrInfo->Node);
        Status = RtlAnsiStringToUnicodeString(&NodeNameUnicode, &NodeNameAnsi, TRUE);

        if (!NT_SUCCESS(Status)) {
            goto Error1;
        }

        NodeName = &NodeNameUnicode;
    }


    // Convert service name to the UNICODE_STRING (if present).
    ANSI_STRING ServiceNameAnsi;
    UNICODE_STRING ServiceNameUnicode;
    PUNICODE_STRING ServiceName = NULL;

    if (AddrInfo->Service) {
        RtlInitAnsiString(&ServiceNameAnsi, AddrInfo->Service);
        Status = RtlAnsiStringToUnicodeString(&ServiceNameUnicode, &ServiceNameAnsi, TRUE);

        if (!NT_SUCCESS(Status)) {
            goto Error2;
        }

        ServiceName = &ServiceNameUnicode;
    }

    // Convert "struct addrinfo" to the "ADDRINFOEXW".
    PADDRINFOEXW Hints;
    Status = APIProxyAddrInfoToAddrInfoEx(AddrInfo->Hints, &Hints);

    if (!NT_SUCCESS(Status)) {
        goto Error3;
    }

    // All data is prepared, call the underlying API.
    PADDRINFOEXW Result;
    Status = KsGetAddrInfo(&AddrInfo->SocketInfo, NodeName, ServiceName, Hints, &Result);

    // Free the memory of the converted "Hints".
    APIProxyFreeAddrInfoEx(Hints);

    if (!NT_SUCCESS(Status)) {
        goto Error3;
    }

    // Convert the result "ADDRINFOEXW" to the "struct addrinfo".
    Status = APIProxyAddrInfoExToAddrInfo(Result, AddrInfo->Result);

    // Free the original result.
    KsFreeAddrInfo(&AddrInfo->SocketInfo, Result);

    if (!NT_SUCCESS(Status)) {
        goto Error3;
    }

    return STATUS_SUCCESS;

Error3:
    if (ServiceName) {
        RtlFreeUnicodeString(&ServiceNameUnicode);
    }

Error2:
    if (NodeName) {
        RtlFreeUnicodeString(&NodeNameUnicode);
    }

Error1:
    return Status;
}

NTSTATUS APIProxyFreeAddrInfo(struct addrinfo* AddrInfo) {

    APIProxyFreeAddrInfoUtility(AddrInfo);

    return STATUS_SUCCESS;
}

NTSTATUS APIProxySocket(WSAStartCleanUp* WSAInfo, PKSOCKET* Socket, int Domain, int Type, int Protocol, _In_ ULONG Flags) {
    NTSTATUS Status;

    Status = KsCreateSocket(WSAInfo, Socket, (ADDRESS_FAMILY)Domain, (USHORT)Type, (ULONG)Protocol, Flags);

    return Status;
}

NTSTATUS APIProxyCloseSocket(PKSOCKET Socket) {
    NTSTATUS Status;

    Status = KsCloseSocket(Socket);

    return Status;
}

NTSTATUS APIProxyConnect(ConnectStruct* ConnectInfo)
{
    NTSTATUS Status;


    Status = KsConnect((PKSOCKET)ConnectInfo->Socket, (PSOCKADDR)ConnectInfo->AddrInfo->ai_addr);

    return Status;

}

NTSTATUS APIProxyListen() {
    return STATUS_SUCCESS;
}

NTSTATUS APIProxyBind(BindStruct* BindInfo) {

    NTSTATUS Status;

    Status = KsBind((PKSOCKET)BindInfo->Socket, (PSOCKADDR)BindInfo->Address);

    return Status;
}

NTSTATUS APIProxyAccept(AcceptStruct* AcceptInfo) {
    
    NTSTATUS Status;

    PKSOCKET NewSocket;

    struct sockaddr_in addr;
    addr.sin_family = AcceptInfo->Address->sin_family;
    addr.sin_addr.s_addr = AcceptInfo->Address->sin_addr.S_un.S_addr;
    addr.sin_port = AcceptInfo->Address->sin_port;


    Status = KsAccept((PKSOCKET)AcceptInfo->Socket, &NewSocket, NULL, (PSOCKADDR)&addr);

    AcceptInfo->NewSocket = (PVOID)NewSocket;
    *AcceptInfo->SocketLen = sizeof(SOCKADDR);

    return Status;
}

NTSTATUS APIProxySend(SendRecvStruct* SendInfo) {
    NTSTATUS Status;

    ULONG Length = (ULONG)SendInfo->BufferLen;
    Status = KsSend((PKSOCKET)SendInfo->Socket, SendInfo->Buffer, &Length, 0);

    return Status;

}

NTSTATUS APIProxyRecv(SendRecvStruct* RecvInfo) {
    NTSTATUS Status;

   
    PVOID RecvData =  (PVOID)ExAllocatePoolWithTag(PagedPool, RecvInfo->BufferLen, MEMORY_TAG);
    if (!RecvData) {
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(RecvData, RecvInfo->BufferLen);
    ULONG Length = (ULONG)RecvInfo->BufferLen;
    
    Status = KsRecv((PKSOCKET)RecvInfo->Socket, (PVOID)RecvData, &Length, 0);

    RtlCopyMemory(RecvInfo->Buffer, RecvData, RecvInfo->BufferLen);
    ExFreePoolWithTag(RecvData, MEMORY_TAG);
     
    return Status;
}
