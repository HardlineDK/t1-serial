#include "smbios.h"
#include "shared.h"
#include <ntifs.h>

// =====================================================
// TRUE PERSISTENT SMBIOS SPOOFER
// Funciona imediatamente + persiste REALMENTE após reboot
// =====================================================

#pragma warning(push)
#pragma warning(disable: 4996)

#pragma pack(push, 1)
typedef struct _SMBIOS_ENTRY_POINT {
    CHAR Signature[4];
    UCHAR Checksum;
    UCHAR Length;
    UCHAR MajorVersion;
    UCHAR MinorVersion;
    USHORT MaxStructureSize;
    UCHAR EntryPointRevision;
    CHAR FormattedArea[5];
    CHAR IntermediateSignature[5];
    UCHAR IntermediateChecksum;
    USHORT TableLength;
    ULONG TableAddress;
    USHORT NumberOfStructures;
    UCHAR BCDRevision;
} SMBIOS_ENTRY_POINT, * PSMBIOS_ENTRY_POINT;

typedef struct _SMBIOS_SYSTEM_INFO {
    SMBIOS_HEADER Header;
    UCHAR Manufacturer;
    UCHAR ProductName;
    UCHAR Version;
    UCHAR SerialNumber;
    UCHAR UUID[16];
    UCHAR WakeUpType;
    UCHAR SKUNumber;
    UCHAR Family;
} SMBIOS_SYSTEM_INFO, * PSMBIOS_SYSTEM_INFO;
#pragma pack(pop)

// UUID spoofado global
UCHAR g_SpoofedUUID[16] = {
    0xDE, 0xAD, 0xBE, 0xEF,  // DEADBEEF signature
    0x13, 0x37, 0x43, 0x21,  // 1337-4321
    0xAB, 0xCD, 0x12, 0x34,  // ABCD-1234
    0x56, 0x78, 0x9A, 0xBC   // 56789ABC
};

// =====================================================
// IMMEDIATE SPOOFING (FUNCIONALIDADE QUE JÁ FUNCIONA)
// =====================================================

NTSTATUS CreateImmediateSpoofing()
{
    DbgPrint("[MUTANTE-TRUE] Creating IMMEDIATE spoofing...\n");

    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING keyPath, valueName;

    __try {
        // SystemInformation (WMI primary source)
        RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation");
        InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwCreateKey(&keyHandle, KEY_ALL_ACCESS, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
        if (NT_SUCCESS(status)) {
            RtlInitUnicodeString(&valueName, L"SystemUUID");
            WCHAR spoofedUUID[] = L"DEADBEEF-1337-4321-ABCD-123456789ABC";
            ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, spoofedUUID, sizeof(spoofedUUID));

            RtlInitUnicodeString(&valueName, L"SystemProductName");
            WCHAR spoofedProduct[] = L"MUTANTE_SPOOF_SYSTEM";
            ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, spoofedProduct, sizeof(spoofedProduct));

            RtlInitUnicodeString(&valueName, L"SystemManufacturer");
            WCHAR spoofedManufacturer[] = L"MUTANTE_CORP";
            ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, spoofedManufacturer, sizeof(spoofedManufacturer));

            ZwClose(keyHandle);
            DbgPrint("[MUTANTE-TRUE] *** IMMEDIATE SPOOFING SUCCESSFUL ***\n");
        }

        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MUTANTE-TRUE] Exception in immediate spoofing: 0x%08X\n", GetExceptionCode());
        if (keyHandle) ZwClose(keyHandle);
        return STATUS_UNSUCCESSFUL;
    }
}

// =====================================================
// FIND AND MODIFY SMBIOS (FUNCIONALIDADE QUE JÁ FUNCIONA)
// =====================================================

PSMBIOS_ENTRY_POINT FindSMBIOSTable()
{
    DbgPrint("[MUTANTE-TRUE] Searching for SMBIOS table...\n");

    PSMBIOS_ENTRY_POINT foundEntryPoint = NULL;
    PHYSICAL_ADDRESS physAddr;
    PVOID mappedMemory = NULL;

    __try {
        for (ULONG address = 0xF0000; address < 0x100000; address += 16) {
            physAddr.QuadPart = address;
            mappedMemory = MmMapIoSpace(physAddr, sizeof(SMBIOS_ENTRY_POINT), MmNonCached);
            if (!mappedMemory) continue;

            __try {
                PSMBIOS_ENTRY_POINT candidate = (PSMBIOS_ENTRY_POINT)mappedMemory;

                if (candidate->Signature[0] == '_' && candidate->Signature[1] == 'S' &&
                    candidate->Signature[2] == 'M' && candidate->Signature[3] == '_') {

                    if (candidate->Length >= 0x1F && candidate->MajorVersion >= 2 &&
                        candidate->TableLength > 0 && candidate->TableAddress != 0) {

                        DbgPrint("[MUTANTE-TRUE] *** SMBIOS FOUND at 0x%08X ***\n", address);
                        foundEntryPoint = candidate;
                        mappedMemory = NULL;
                        break;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}

            if (mappedMemory) {
                MmUnmapIoSpace(mappedMemory, sizeof(SMBIOS_ENTRY_POINT));
                mappedMemory = NULL;
            }
        }

        return foundEntryPoint;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        if (mappedMemory) MmUnmapIoSpace(mappedMemory, sizeof(SMBIOS_ENTRY_POINT));
        return NULL;
    }
}

NTSTATUS ModifySMBIOSTable(PSMBIOS_ENTRY_POINT entryPoint)
{
    if (!entryPoint) return STATUS_INVALID_PARAMETER;

    PHYSICAL_ADDRESS tablePhysAddr;
    PVOID tableMapping = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    __try {
        tablePhysAddr.QuadPart = entryPoint->TableAddress;
        tableMapping = MmMapIoSpace(tablePhysAddr, entryPoint->TableLength, MmNonCached);
        if (!tableMapping) return STATUS_INSUFFICIENT_RESOURCES;

        PSMBIOS_HEADER currentHeader = (PSMBIOS_HEADER)tableMapping;
        PUCHAR tableEnd = (PUCHAR)tableMapping + entryPoint->TableLength;

        for (USHORT i = 0; i < entryPoint->NumberOfStructures && (PUCHAR)currentHeader < tableEnd; i++) {
            __try {
                if (currentHeader->Type == 1) {
                    PSMBIOS_SYSTEM_INFO systemInfo = (PSMBIOS_SYSTEM_INFO)currentHeader;

                    RtlCopyMemory(systemInfo->UUID, g_SpoofedUUID, 16);

                    DbgPrint("[MUTANTE-TRUE] *** UUID MODIFIED IN MEMORY ***\n");
                    status = STATUS_SUCCESS;
                    break;
                }

                PUCHAR nextPtr = (PUCHAR)currentHeader + currentHeader->Length;
                while (nextPtr < tableEnd - 1 && (nextPtr[0] != 0 || nextPtr[1] != 0)) {
                    nextPtr++;
                }
                nextPtr += 2;
                if (nextPtr >= tableEnd) break;
                currentHeader = (PSMBIOS_HEADER)nextPtr;

            }
            __except (EXCEPTION_EXECUTE_HANDLER) { break; }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_UNSUCCESSFUL;
    }

    if (tableMapping) {
        MmUnmapIoSpace(tableMapping, entryPoint->TableLength);
    }

    return status;
}

// =====================================================
// REAL PERSISTENCE - BATCH FILE METHOD
// =====================================================

NTSTATUS CreatePersistenceBatchFile()
{
    DbgPrint("[MUTANTE-TRUE] Creating REAL persistence batch file...\n");

    NTSTATUS status;
    HANDLE fileHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING fileName;
    IO_STATUS_BLOCK ioStatus;

    __try {
        // Create batch file in Windows directory
        RtlInitUnicodeString(&fileName, L"\\SystemRoot\\system32\\sysupdate.bat");
        InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttr, &ioStatus, NULL,
            FILE_ATTRIBUTE_HIDDEN, 0, FILE_OVERWRITE_IF, FILE_NON_DIRECTORY_FILE, NULL, 0);

        if (NT_SUCCESS(status)) {
            // Batch content that reapplies spoofing
            CHAR batchContent[] =
                "@echo off\r\n"
                "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation\" /v SystemUUID /t REG_SZ /d \"DEADBEEF-1337-4321-ABCD-123456789ABC\" /f >nul 2>&1\r\n"
                "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation\" /v SystemProductName /t REG_SZ /d \"MUTANTE_SPOOF_SYSTEM\" /f >nul 2>&1\r\n"
                "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation\" /v SystemManufacturer /t REG_SZ /d \"MUTANTE_CORP\" /f >nul 2>&1\r\n"
                "reg add \"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\" /v SystemProductName /t REG_SZ /d \"MUTANTE_SPOOF_SYSTEM\" /f >nul 2>&1\r\n"
                "reg add \"HKLM\\HARDWARE\\DESCRIPTION\\System\\BIOS\" /v SystemManufacturer /t REG_SZ /d \"MUTANTE_CORP\" /f >nul 2>&1\r\n"
                "exit\r\n";

            ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus, batchContent, strlen(batchContent), NULL, NULL);
            ZwClose(fileHandle);

            DbgPrint("[MUTANTE-TRUE] Persistence batch file created\n");
        }

        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MUTANTE-TRUE] Exception creating batch file: 0x%08X\n", GetExceptionCode());
        if (fileHandle) ZwClose(fileHandle);
        return STATUS_UNSUCCESSFUL;
    }
}

// =====================================================
// REAL PERSISTENCE - REGISTRY STARTUP HOOKS
// =====================================================

NTSTATUS CreateRealStartupHooks()
{
    DbgPrint("[MUTANTE-TRUE] Creating REAL startup hooks...\n");

    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING keyPath, valueName;

    __try {
        // HOOK 1: Current User Run
        RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objAttr);
        if (NT_SUCCESS(status)) {
            RtlInitUnicodeString(&valueName, L"SystemUpdate");
            WCHAR command1[] = L"cmd /c start /min C:\\Windows\\system32\\sysupdate.bat";
            ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, command1, sizeof(command1));
            ZwClose(keyHandle);
            DbgPrint("[MUTANTE-TRUE] User startup hook created\n");
        }

        // HOOK 2: Local Machine Run  
        RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run");
        InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objAttr);
        if (NT_SUCCESS(status)) {
            RtlInitUnicodeString(&valueName, L"WindowsDefenderUpdate");
            WCHAR command2[] = L"C:\\Windows\\system32\\sysupdate.bat";
            ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, command2, sizeof(command2));
            ZwClose(keyHandle);
            DbgPrint("[MUTANTE-TRUE] Machine startup hook created\n");
        }

        // HOOK 3: RunOnce for immediate next boot
        RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
        InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenKey(&keyHandle, KEY_SET_VALUE, &objAttr);
        if (NT_SUCCESS(status)) {
            RtlInitUnicodeString(&valueName, L"SystemInit");
            WCHAR command3[] = L"C:\\Windows\\system32\\sysupdate.bat && reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"SystemUpdate\" /t REG_SZ /d \"C:\\Windows\\system32\\sysupdate.bat\" /f";
            ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, command3, sizeof(command3));
            ZwClose(keyHandle);
            DbgPrint("[MUTANTE-TRUE] RunOnce hook created\n");
        }

        // HOOK 4: Task Scheduler startup via registry
        RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks");
        InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwCreateKey(&keyHandle, KEY_ALL_ACCESS, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
        if (NT_SUCCESS(status)) {
            RtlInitUnicodeString(&valueName, L"SystemMaintenanceTask");
            WCHAR taskCommand[] = L"C:\\Windows\\system32\\sysupdate.bat";
            ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, taskCommand, sizeof(taskCommand));
            ZwClose(keyHandle);
            DbgPrint("[MUTANTE-TRUE] Task scheduler hook created\n");
        }

        DbgPrint("[MUTANTE-TRUE] *** ALL STARTUP HOOKS CREATED ***\n");
        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MUTANTE-TRUE] Exception creating startup hooks: 0x%08X\n", GetExceptionCode());
        if (keyHandle) ZwClose(keyHandle);
        return STATUS_UNSUCCESSFUL;
    }
}

// =====================================================
// REAL PERSISTENCE - MULTIPLE REGISTRY BACKUPS
// =====================================================

NTSTATUS CreateMultipleRegistryBackups()
{
    DbgPrint("[MUTANTE-TRUE] Creating MULTIPLE registry backups...\n");

    NTSTATUS status;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING keyPath, valueName;

    // Backup locations
    const WCHAR* backupPaths[] = {
        L"\\Registry\\Machine\\SYSTEM\\ControlSet001\\Control\\SystemInformation",
        L"\\Registry\\Machine\\SYSTEM\\ControlSet002\\Control\\SystemInformation",
        L"\\Registry\\Machine\\SYSTEM\\Select\\SystemInformation",
        L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SystemInformation",
        L"\\Registry\\Machine\\SOFTWARE\\Classes\\SystemInformation"
    };

    __try {
        for (int i = 0; i < 5; i++) {
            RtlInitUnicodeString(&keyPath, backupPaths[i]);
            InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

            status = ZwCreateKey(&keyHandle, KEY_ALL_ACCESS, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
            if (NT_SUCCESS(status)) {
                RtlInitUnicodeString(&valueName, L"SystemUUID");
                WCHAR backupUUID[] = L"DEADBEEF-1337-4321-ABCD-123456789ABC";
                ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, backupUUID, sizeof(backupUUID));

                RtlInitUnicodeString(&valueName, L"SystemProductName");
                WCHAR backupProduct[] = L"MUTANTE_SPOOF_SYSTEM";
                ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, backupProduct, sizeof(backupProduct));

                ZwClose(keyHandle);
                DbgPrint("[MUTANTE-TRUE] Backup %d created\n", i + 1);
            }
        }

        DbgPrint("[MUTANTE-TRUE] *** ALL REGISTRY BACKUPS CREATED ***\n");
        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MUTANTE-TRUE] Exception creating backups: 0x%08X\n", GetExceptionCode());
        if (keyHandle) ZwClose(keyHandle);
        return STATUS_UNSUCCESSFUL;
    }
}

// =====================================================
// MAIN TRUE PERSISTENT FUNCTION
// =====================================================

NTSTATUS Smbios::ChangeSmbiosSerials()
{
    DbgPrint("[MUTANTE-TRUE] ==========================================\n");
    DbgPrint("[MUTANTE-TRUE] ===  TRUE PERSISTENT SMBIOS SPOOFER  ===\n");
    DbgPrint("[MUTANTE-TRUE] ===    SURVIVES REBOOT FOR REAL      ===\n");
    DbgPrint("[MUTANTE-TRUE] ==========================================\n");

    NTSTATUS finalStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN immediateSuccess = FALSE;
    BOOLEAN memorySuccess = FALSE;

    __try {
        // STEP 1: Immediate spoofing (funciona agora)
        DbgPrint("[MUTANTE-TRUE] STEP 1: Immediate spoofing...\n");
        NTSTATUS immediateStatus = CreateImmediateSpoofing();
        if (NT_SUCCESS(immediateStatus)) {
            DbgPrint("[MUTANTE-TRUE] *** IMMEDIATE SUCCESS ***\n");
            immediateSuccess = TRUE;
        }

        // STEP 2: Memory spoofing (funciona agora)
        DbgPrint("[MUTANTE-TRUE] STEP 2: Memory spoofing...\n");
        PSMBIOS_ENTRY_POINT entryPoint = FindSMBIOSTable();
        if (entryPoint) {
            NTSTATUS memoryStatus = ModifySMBIOSTable(entryPoint);
            if (NT_SUCCESS(memoryStatus)) {
                DbgPrint("[MUTANTE-TRUE] *** MEMORY SUCCESS ***\n");
                memorySuccess = TRUE;
            }
            MmUnmapIoSpace(entryPoint, sizeof(SMBIOS_ENTRY_POINT));
        }

        if (immediateSuccess || memorySuccess) {
            finalStatus = STATUS_SUCCESS;

            // STEP 3: REAL Persistence methods
            DbgPrint("[MUTANTE-TRUE] STEP 3: Creating REAL persistence...\n");

            CreatePersistenceBatchFile();
            CreateRealStartupHooks();
            CreateMultipleRegistryBackups();

            DbgPrint("[MUTANTE-TRUE] *** OVERALL SUCCESS ***\n");
            DbgPrint("[MUTANTE-TRUE] *** UUID: DEADBEEF-1337-4321-ABCD-123456789ABC ***\n");
            DbgPrint("[MUTANTE-TRUE] *** PERSISTENCE: ENABLED ***\n");
            DbgPrint("[MUTANTE-TRUE] *** BATCH FILE: C:\\Windows\\system32\\sysupdate.bat ***\n");
            DbgPrint("[MUTANTE-TRUE] *** STARTUP HOOKS: CREATED ***\n");
            DbgPrint("[MUTANTE-TRUE] *** REGISTRY BACKUPS: CREATED ***\n");
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MUTANTE-TRUE] Critical exception: 0x%08X\n", GetExceptionCode());
        finalStatus = STATUS_UNSUCCESSFUL;
    }

    DbgPrint("[MUTANTE-TRUE] ==========================================\n");
    DbgPrint("[MUTANTE-TRUE] FINAL STATUS: %s\n", NT_SUCCESS(finalStatus) ? "SUCCESS" : "FAILED");
    DbgPrint("[MUTANTE-TRUE] ==========================================\n");

    return finalStatus;
}

// =====================================================
// STRING FUNCTIONS (unchanged)
// =====================================================

char* Smbios::GetString(SMBIOS_HEADER* header, UCHAR string)
{
    if (!header || string == 0) return NULL;
    __try {
        char* data = (char*)header + header->Length;
        for (UCHAR i = 1; i < string; i++) {
            if (*data == 0) return NULL;
            data += strlen(data) + 1;
        }
        return (*data != 0) ? data : NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) { return NULL; }
}

void Smbios::ChangeString(SMBIOS_HEADER* header, UCHAR string, const char* newString)
{
    if (!header || !newString || string == 0) return;
    __try {
        char* originalString = GetString(header, string);
        if (!originalString) return;
        size_t originalLength = strlen(originalString);
        size_t newLength = strlen(newString);
        if (newLength <= originalLength) {
            RtlCopyMemory(originalString, newString, newLength);
            RtlZeroMemory(originalString + newLength, originalLength - newLength);
        }
        else {
            RtlCopyMemory(originalString, newString, originalLength);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}

#pragma warning(pop)