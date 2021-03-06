#include "GayFag.h"

UNICODE_STRING  symbolic_link, device_name;

NTSTATUS control_input_output(PDEVICE_OBJECT device_object, PIRP input_request_p) {
	input_request_p->IoStatus.Status = STATUS_SUCCESS;
	input_request_p->IoStatus.Information = sizeof(info);

	auto stack = IoGetCurrentIrpStackLocation(input_request_p);

	auto BaffeR = (p_info)input_request_p->AssociatedIrp.SystemBuffer;

	if (stack) {
		if (BaffeR && sizeof(*BaffeR) >= sizeof(info)) {

			if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_read) {
				if (BaffeR->address != nullptr)
				{
					read_mem(BaffeR->pid, BaffeR->address, BaffeR->value, BaffeR->size);
				}
				else
				{
					BaffeR->value = nullptr;
				}
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_write) {
				write_mem(BaffeR->pid, BaffeR->address, BaffeR->value, BaffeR->size);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_write_protected) {
				write_memprotected(BaffeR->pid, BaffeR->address, BaffeR->value, BaffeR->size);
				//write_mem(BaffeR->pid, BaffeR->address, BaffeR->value, BaffeR->size);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_base) {
				get_base(BaffeR->pid, BaffeR->value);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_up_base) {
				UNICODE_STRING mod;
				RtlInitUnicodeString(&mod, L"UnityPlayer.dll");
				get_modulebase(BaffeR->pid, BaffeR->value, mod);
			}
			else if (stack->Parameters.DeviceIoControl.IoControlCode == ctl_ga_base) {
				UNICODE_STRING mod;
				RtlInitUnicodeString(&mod, L"GameAssembly.dll");
				get_modulebase(BaffeR->pid, BaffeR->value, mod);
			}
		}
	}

	IoCompleteRequest(input_request_p, IO_NO_INCREMENT);
	return input_request_p->IoStatus.Status;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	IoDeleteSymbolicLink(&symbolic_link);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

//DriverEntry
NTSTATUS Feggggot(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
	auto  status = STATUS_SUCCESS;
	
	PDEVICE_OBJECT  device_object;

	RtlInitUnicodeString(&device_name, L"\\Device\\CrudeOil");
	status = IoCreateDevice(driver_obj, 0, &device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\CrudeOil");
	status = IoCreateSymbolicLink(&symbolic_link, &device_name);

	if (status != STATUS_SUCCESS) {
		return status;
	}

	device_object->Flags |= DO_BUFFERED_IO;

	for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
		driver_obj->MajorFunction[t] = unsupported_io;

	driver_obj->MajorFunction[IRP_MJ_CREATE] = create_input_output;
	driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_input_output;
	driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = control_input_output;
	driver_obj->DriverUnload = DriverUnload;
	device_object->Flags &= ~DO_DEVICE_INITIALIZING;
	return status;
}


NTSTATUS unsupported_io(PDEVICE_OBJECT device_object, PIRP input_request_p) {
	input_request_p->IoStatus.Status = STATUS_NOT_SUPPORTED;
	IoCompleteRequest(input_request_p, IO_NO_INCREMENT);
	return input_request_p->IoStatus.Status;
}

NTSTATUS create_input_output(PDEVICE_OBJECT device_object, PIRP input_request_p) {
	UNREFERENCED_PARAMETER(device_object);

	IoCompleteRequest(input_request_p, IO_NO_INCREMENT);
	return input_request_p->IoStatus.Status;
}

NTSTATUS close_input_output(PDEVICE_OBJECT device_object, PIRP input_request_p) {
	UNREFERENCED_PARAMETER(device_object);
	IoCompleteRequest(input_request_p, IO_NO_INCREMENT);
	return input_request_p->IoStatus.Status;
}

uintptr_t get_kerneladdr(const char* name, size_t& size) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
	);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, pooltag);

	if (!pModuleList) {
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);

	ULONG i = 0;
	uintptr_t address = 0;

	for (i = 0; i < pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = uintptr_t(pModuleList->Modules[i].Base);
		size = uintptr_t(pModuleList->Modules[i].Size);
		if (strstr(mod.ImageName, name) != NULL)
			break;
	}

	ExFreePoolWithTag(pModuleList, pooltag);

	return address;
}

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;

typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32
{
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

extern "C"
{
	NTKERNELAPI
	PPEB
	NTAPI
	PsGetProcessPeb(IN PEPROCESS Process);
}

PVOID BBGetUserModule(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName)
{
	ASSERT(pProcess != NULL);
	if (pProcess == NULL)
		return NULL;

	// Protect from UserMode AV
	__try
	{
		// Native process
		PPEB pPeb = PsGetProcessPeb(pProcess);
		if (!pPeb)
		{
			return 0;
		}
		if (!pPeb->Ldr)
		{
			return 0;
		}
		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
			pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
				return pEntry->DllBase;
		}
		return 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

ULONG BBGetUserModuleSize(IN PEPROCESS pProcess, IN PUNICODE_STRING ModuleName)
{
	ASSERT(pProcess != NULL);
	if (pProcess == NULL)
		return NULL;

	// Protect from UserMode AV
	__try
	{
		// Native process
		PPEB pPeb = PsGetProcessPeb(pProcess);
		if (!pPeb)
		{
			return 0;
		}
		if (!pPeb->Ldr)
		{
			return 0;
		}
		for (PLIST_ENTRY pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
			pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
			if (RtlCompareUnicodeString(&pEntry->BaseDllName, ModuleName, TRUE) == 0)
				return pEntry->SizeOfImage;
		}
		return 0;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

//for wrecking l33t anticheese
void ClearCR0Bit()
{
	ULONG_PTR dwCr0 = __readcr0();
	dwCr0 &= 0xFFFEFFFF;
	__writecr0(dwCr0);
}

void RestoreCR0Bit()
{
	ULONG_PTR dwCr0 = __readcr0();
	dwCr0 |= 0x00010000;
	__writecr0(dwCr0);
}

void get_base(int pid, void* value) {
	PEPROCESS t_process;
	PsLookupProcessByProcessId((HANDLE)pid, &t_process);
	PVOID base_address = PsGetProcessSectionBaseAddress(t_process);
	RtlCopyMemory(value, &base_address, 8);
	ObfDereferenceObject(t_process);
}

void get_modulebase(int pid, void* value, UNICODE_STRING mod) {
	PEPROCESS t_process;
	//UNICODE_STRING mod;
	KAPC_STATE apc;

	//RtlInitUnicodeString(&mod, L"notepad.exe"); //this works

	PsLookupProcessByProcessId((HANDLE)pid, &t_process);
	KeStackAttachProcess(t_process, &apc);

	PVOID base_address = BBGetUserModule(t_process, &mod);

	KeUnstackDetachProcess(&apc);
	RtlCopyMemory(value, &base_address, 8);
	ObfDereferenceObject(t_process);
}

void get_modulesize(int pid, void* value, UNICODE_STRING mod) {
	PEPROCESS t_process;
	KAPC_STATE apc;

	PsLookupProcessByProcessId((HANDLE)pid, &t_process);
	KeStackAttachProcess(t_process, &apc);

	ULONG base_address = BBGetUserModuleSize(t_process, &mod);

	KeUnstackDetachProcess(&apc);
	RtlCopyMemory(value, &base_address, 8);
	ObfDereferenceObject(t_process);
}

void write_mem(int pid, void* addr, void* value, size_t size) {
	PEPROCESS t_process;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &t_process);
	MmCopyVirtualMemory(PsGetCurrentProcess(), value, t_process, addr, size, KernelMode, &bytes);
	ObfDereferenceObject(t_process);
}

void write_memprotected(int pid, void* addr, void* value, size_t size) {
	PEPROCESS t_process;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &t_process);
	ClearCR0Bit();
	MmCopyVirtualMemory(PsGetCurrentProcess(), value, t_process, addr, size, KernelMode, &bytes);
	RestoreCR0Bit();
	ObfDereferenceObject(t_process);
}

void read_mem(int pid, void* addr, void* value, size_t size) {
	PEPROCESS t_process;
	SIZE_T bytes;
	PsLookupProcessByProcessId((HANDLE)pid, &t_process);

	size_t chunksize = 1024;
	if (size >= chunksize)
	{
		size_t blocks = (size / chunksize);
		for (size_t i = 0; i < blocks; i++)
		{
			MmCopyVirtualMemory(t_process, (PVOID)((__int64)addr + (i * chunksize)), PsGetCurrentProcess(), (PVOID)((__int64)value + (i * chunksize)), chunksize, KernelMode, &bytes);
		}
		size_t leftoverbytes = size - (chunksize * blocks);
		if (leftoverbytes > 0)
		{
			MmCopyVirtualMemory(t_process, (PVOID)((__int64)addr + (chunksize * blocks)), PsGetCurrentProcess(), (PVOID)((__int64)value + (chunksize * blocks)), leftoverbytes, KernelMode, &bytes);
		}
	}
	else
	{
		MmCopyVirtualMemory(t_process, addr, PsGetCurrentProcess(), value, size, KernelMode, &bytes);
	}

	ObfDereferenceObject(t_process);
}
