#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntdddisk.h>
#include <scsi.h>
#include <intrin.h>
#include "NiGGaS.h"

typedef unsigned __int64 uintptr_t;

typedef struct info_t {
	UINT64 pid = 0;
	void* address;
	void* value;
	SIZE_T size;
}info, *p_info;

#define ctl_write_protected   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0823, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_write   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0824, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_read    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0825, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_base    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0826, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_up_base    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0827, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ctl_ga_base    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0828, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define pooltag 'G4Y'

NTSTATUS unsupported_io(PDEVICE_OBJECT device_object, PIRP input_request_p);
NTSTATUS create_input_output(PDEVICE_OBJECT device_object, PIRP input_request_p);
NTSTATUS close_input_output(PDEVICE_OBJECT device_object, PIRP input_request_p);

void write_mem(int pid, void* addr, void* value, size_t size);
void write_memprotected(int pid, void* addr, void* value, size_t size);
void read_mem(int pid, void* addr, void* value, size_t size);
void get_base(int pid, void* value);
void get_modulebase(int pid, void* value, UNICODE_STRING mod);
void get_modulesize(int pid, void* value, UNICODE_STRING mod);

uintptr_t get_kerneladdr(const char* name, size_t& size);

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	NTKERNELAPI NTSTATUS ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	NTKERNELAPI NTSTATUS ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID * Object);
	NTKERNELAPI NTSTATUS MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
}
