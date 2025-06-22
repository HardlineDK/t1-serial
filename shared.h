#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

// Pool tag for memory allocations
#define POOL_TAG 'etuM'

// Forward declarations
typedef struct _RAID_UNIT_EXTENSION RAID_UNIT_EXTENSION, * PRAID_UNIT_EXTENSION;

// Function typedefs
typedef NTSTATUS(*RaidUnitRegisterInterfaces)(PRAID_UNIT_EXTENSION);
typedef NTSTATUS(*DiskEnableDisableFailurePrediction)(PVOID, BOOLEAN);

// SMBIOS structures
typedef struct _SMBIOS_HEADER
{
    UCHAR Type;
    UCHAR Length;
    USHORT Handle;
} SMBIOS_HEADER, * PSMBIOS_HEADER;

// Disk identity structures
typedef struct _STOR_SCSI_IDENTITY
{
    STRING SerialNumber;
} STOR_SCSI_IDENTITY, * PSTOR_SCSI_IDENTITY;

typedef struct _RAID_IDENTITY
{
    STOR_SCSI_IDENTITY Identity;
} RAID_IDENTITY, * PRAID_IDENTITY;

// Smart/Telemetry structures
typedef struct _SMART_TELEMETRY
{
    ULONG SmartMask;
    UCHAR Reserved[64];
} SMART_TELEMETRY, * PSMART_TELEMETRY;

typedef struct _SMART_DATA
{
    SMART_TELEMETRY Telemetry;
    UCHAR Reserved[128];
} SMART_DATA, * PSMART_DATA;

// Main RAID unit extension structure
typedef struct _RAID_UNIT_EXTENSION
{
    UCHAR Reserved1[0x68];
    RAID_IDENTITY _Identity;
    UCHAR Reserved2[0x120];
    SMART_DATA _Smart;
    UCHAR Reserved3[0x200];
} RAID_UNIT_EXTENSION, * PRAID_UNIT_EXTENSION;

// System information structures
typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemModuleInformation = 11
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID Base;
    ULONG Size;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
    CHAR ImageName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG ulModuleCount;
    SYSTEM_MODULE_ENTRY Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
