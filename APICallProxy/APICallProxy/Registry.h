#pragma once


NTSTATUS APIProxyCreateKey(_In_ OpenCreateRegistryInfo* CreateKeyInfo, _Inout_ HANDLE* NewKeyHandle) {

	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING name;
	ULONG Disposition;
	NTSTATUS Status = STATUS_SUCCESS;

	__try {
	RtlInitUnicodeString(&name, CreateKeyInfo->RegistryKeyPath);
	InitializeObjectAttributes(&objectAttributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);

	Status = ZwCreateKey(
		NewKeyHandle,
		CreateKeyInfo->DesiredAccess,
		&objectAttributes,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		&Disposition);

#if DEBUG
	if (!NT_SUCCESS(Status)) {
		DbgPrint("APICallProxy: Error Create Registry Key Status Code 0x%x\n", Status);
	}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Create Registry Key Status Code 0x%x\n", Status);

#endif

	}

	return Status;
}

NTSTATUS APIProxyOpenKey(_In_ OpenCreateRegistryInfo* OpenKeyInfo, _Inout_ HANDLE* NewKeyHandle) {

	OBJECT_ATTRIBUTES objectAttributes;
	UNICODE_STRING name;
	NTSTATUS Status = STATUS_SUCCESS;

	__try {

		RtlInitUnicodeString(&name, OpenKeyInfo->RegistryKeyPath);
		InitializeObjectAttributes(&objectAttributes, &name, OBJ_KERNEL_HANDLE, NULL, NULL);

		Status = ZwOpenKey(NewKeyHandle, OpenKeyInfo->DesiredAccess, &objectAttributes);

#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Open Registry Key Status Code 0x%x\n", Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Open Registry Key Status Code 0x%x\n", Status);

#endif

	}

	return Status;
}

NTSTATUS APIProxyDeleteRegistryKey(_In_ HANDLE KeyHandle) {

	NTSTATUS Status = STATUS_SUCCESS;

	__try {

		Status = ZwDeleteKey(KeyHandle);

#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Delete Registry Key Status Code 0x%x\n", Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Delete Registry Key Status Code 0x%x\n", Status);

#endif

	}

	return Status;
}

NTSTATUS APIProxyRegistrySetValue(_In_ RegistrySetValueInfo* SetValueInfo) {

	UNICODE_STRING ValueName;
	NTSTATUS Status = STATUS_SUCCESS;

	__try {

		RtlInitUnicodeString(&ValueName, SetValueInfo->KeyName);
		Status = ZwSetValueKey(
			SetValueInfo->KeyHandle,
			&ValueName,
			0,
			SetValueInfo->Type,
			SetValueInfo->Date,
			SetValueInfo->DateSize);

#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Set Registry Key Status Code 0x%x\n", Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Setting Registry Key Status Code 0x%x\n", Status);

#endif

	}

	return Status;
}

NTSTATUS APIProxyRegistryQueryValue(_In_ RegistryQueryKeyValueInfo* QueryValueInfo) {

	UNICODE_STRING ValueName;
	NTSTATUS Status = STATUS_SUCCESS;

	__try {


		RtlInitUnicodeString(&ValueName, QueryValueInfo->ValueName);
		Status = ZwQueryValueKey(
			QueryValueInfo->KeyHandle, 
			&ValueName, 
			(KEY_VALUE_INFORMATION_CLASS)QueryValueInfo->KeyValueInformationClass,
			QueryValueInfo->Data,
			QueryValueInfo->DateSize,
			QueryValueInfo->ResultLength);

#if DEBUG
		if (!NT_SUCCESS(Status)) {
			DbgPrint("APICallProxy: Error Query Registry Key Status Code 0x%x\n", Status);
		}
#endif 

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = STATUS_ACCESS_VIOLATION;
#if DEBUG
		DbgPrint("APICallProxy: Error Access Violation while Query Registry Key Status Code 0x%x\n", Status);

#endif

	}

	return Status;
}