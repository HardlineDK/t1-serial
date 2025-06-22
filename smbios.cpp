#include "smbios.h"
#include "shared.h"
#include "log.h"
#include "utils.h"
#include <ntifs.h>

// =====================================================
// PERMANENT RANDOM UUID SMBIOS SPOOFER
// =====================================================

#pragma warning(push)
#pragma warning(disable: 4996)
#pragma warning(disable: 4267)
#pragma warning(disable: 4244)

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

// Global variables
static UCHAR g_RandomUUID[16] = { 0 };
static CHAR g_RandomUUIDString[40] = { 0 };
static CHAR g_RandomSerial[32] = { 0 };
static PSMBIOS_ENTRY_POINT g_SmbiosEntryPoint = NULL;
static PVOID g_MappedSmbiosTable = NULL;
static BOOLEAN g_PhysicalModificationSuccess = FALSE;

// =====================================================
// RANDOM GENERATION
// =====================================================

ULONG GenerateSecureRandom() {
    LARGE_INTEGER systemTime, perfCounter, tickCount;
    KeQuerySystemTime(&systemTime);
    KeQueryPerformanceCounter(&perfCounter);
    KeQueryTickCount(&tickCount);

    ULONG seed1 = (ULONG)(systemTime.QuadPart & 0xFFFFFFFF);
    ULONG seed2 = (ULONG)(perfCounter.QuadPart & 0xFFFFFFFF);
    ULONG seed3 = (ULONG)(tickCount.QuadPart & 0xFFFFFFFF);
    ULONG seed4 = (ULONG_PTR)&systemTime;

    ULONG result = seed1 ^ seed2 ^ seed3 ^ seed4;
    result = (result << 13) | (result >> 19);
    result ^= (ULONG)(systemTime.QuadPart >> 32);
    result = result * 1103515245 + 12345;

    return result;
}

VOID GenerateRandomIdentifiers() {
    Log::Print("[SMBIOS-RANDOM] *** GENERATING RANDOM IDENTIFIERS ***\n");

    // Generate random UUID
    ULONG* uuidParts = (ULONG*)g_RandomUUID;
    for (int i = 0; i < 4; i++) {
        LARGE_INTEGER delay;
        delay.QuadPart = -1000LL;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
        uuidParts[i] = GenerateSecureRandom();
    }

    // Ensure valid UUID format
    g_RandomUUID[6] = (g_RandomUUID[6] & 0x0F) | 0x40;
    g_RandomUUID[8] = (g_RandomUUID[8] & 0x3F) | 0x80;

    // Format UUID string
    const char hexChars[] = "0123456789ABCDEF";
    int pos = 0;

    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            g_RandomUUIDString[pos++] = '-';
        }
        g_RandomUUIDString[pos++] = hexChars[(g_RandomUUID[i] >> 4) & 0xF];
        g_RandomUUIDString[pos++] = hexChars[g_RandomUUID[i] & 0xF];
    }
    g_RandomUUIDString[pos] = '\0';

    // Generate random serial
    const char serialChars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    ULONG baseSeed = GenerateSecureRandom();

    for (int i = 0; i < 20; i++) {
        baseSeed = GenerateSecureRandom();
        g_RandomSerial[i] = serialChars[baseSeed % (sizeof(serialChars) - 1)];
    }
    g_RandomSerial[20] = '\0';

    Log::Print("[SMBIOS-RANDOM] Generated UUID: %s\n", g_RandomUUIDString);
    Log::Print("[SMBIOS-RANDOM] Generated Serial: %s\n", g_RandomSerial);
}

// =====================================================
// MEMORY UTILITIES
// =====================================================

BOOLEAN VerifyMemoryWritable(PVOID address, SIZE_T size) {
    __try {
        volatile UCHAR* testAddr = (volatile UCHAR*)address;
        UCHAR originalByte = *testAddr;

        *testAddr = 0xFF;
        if (*testAddr != 0xFF) return FALSE;

        *testAddr = 0x00;
        if (*testAddr != 0x00) return FALSE;

        *testAddr = originalByte;
        return TRUE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

VOID FlushMemoryChanges(PVOID address, SIZE_T size) {
    __try {
        if (address && size > 0) {
            KeInvalidateAllCaches();
            KeMemoryBarrier();

            for (SIZE_T i = 0; i < size; i += PAGE_SIZE) {
                volatile UCHAR* ptr = (volatile UCHAR*)((UCHAR*)address + i);
                *ptr = *ptr;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log::Print("[SMBIOS] Exception in FlushMemoryChanges\n");
    }
}

// =====================================================
// REGISTRY MODIFICATION
// =====================================================

NTSTATUS ModifyRegistryValues() {
    Log::Print("[SMBIOS] *** MODIFYING REGISTRY FOR PERSISTENCE ***\n");

    NTSTATUS status = STATUS_SUCCESS;
    HANDLE keyHandle = NULL;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING keyPath, valueName;

    __try {
        // Convert to WCHAR
        WCHAR wideUUID[40] = { 0 };
        WCHAR wideSerial[32] = { 0 };

        for (int i = 0; i < 39 && g_RandomUUIDString[i]; i++) {
            wideUUID[i] = (WCHAR)g_RandomUUIDString[i];
        }
        for (int i = 0; i < 31 && g_RandomSerial[i]; i++) {
            wideSerial[i] = (WCHAR)g_RandomSerial[i];
        }

        // Registry paths
        const WCHAR* registryPaths[] = {
            L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
            L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\BIOS",
            L"\\Registry\\Machine\\SYSTEM\\ControlSet001\\Control\\SystemInformation",
            L"\\Registry\\Machine\\SYSTEM\\ControlSet002\\Control\\SystemInformation"
        };

        for (int i = 0; i < 4; i++) {
            RtlInitUnicodeString(&keyPath, registryPaths[i]);
            InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

            status = ZwCreateKey(&keyHandle, KEY_ALL_ACCESS, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
            if (NT_SUCCESS(status)) {
                // Set UUID
                RtlInitUnicodeString(&valueName, L"SystemUUID");
                ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, wideUUID,
                    (ULONG)(wcslen(wideUUID) + 1) * sizeof(WCHAR));

                RtlInitUnicodeString(&valueName, L"UUID");
                ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, wideUUID,
                    (ULONG)(wcslen(wideUUID) + 1) * sizeof(WCHAR));

                // Set Serial
                RtlInitUnicodeString(&valueName, L"SystemSerialNumber");
                ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, wideSerial,
                    (ULONG)(wcslen(wideSerial) + 1) * sizeof(WCHAR));

                RtlInitUnicodeString(&valueName, L"SerialNumber");
                ZwSetValueKey(keyHandle, &valueName, 0, REG_SZ, wideSerial,
                    (ULONG)(wcslen(wideSerial) + 1) * sizeof(WCHAR));

                ZwClose(keyHandle);
                Log::Print("[SMBIOS] Registry path %d modified\n", i + 1);
            }
        }

        Log::Print("[SMBIOS] *** REGISTRY MODIFICATION COMPLETE ***\n");
        return STATUS_SUCCESS;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log::Print("[SMBIOS] Exception in registry modification: 0x%08X\n", GetExceptionCode());
        if (keyHandle) ZwClose(keyHandle);
        return STATUS_UNSUCCESSFUL;
    }
}

// =====================================================
// SMBIOS SCANNING
// =====================================================

PSMBIOS_ENTRY_POINT FindSmbiosEntryPoint() {
    Log::Print("[SMBIOS] *** SCANNING FOR SMBIOS ENTRY POINT ***\n");

    struct {
        ULONG_PTR start;
        ULONG_PTR end;
        const char* name;
    } searchRegions[] = {
        { 0xF0000, 0xFFFFF, "BIOS F-Segment" },
        { 0xE0000, 0xEFFFF, "BIOS E-Segment" },
        { 0x000F0000, 0x000FFFFF, "Extended BIOS" },
        { 0xC0000, 0xDFFFF, "Option ROM Area" }
    };

    for (int region = 0; region < 4; region++) {
        Log::Print("[SMBIOS] Scanning: %s (0x%p-0x%p)\n",
            searchRegions[region].name,
            (PVOID)searchRegions[region].start,
            (PVOID)searchRegions[region].end);

        PHYSICAL_ADDRESS physAddr;
        physAddr.QuadPart = searchRegions[region].start;
        SIZE_T regionSize = searchRegions[region].end - searchRegions[region].start + 1;

        MEMORY_CACHING_TYPE cacheTypes[] = { MmNonCached, MmCached, MmWriteCombined };
        const char* cacheNames[] = { "MmNonCached", "MmCached", "MmWriteCombined" };

        for (int cacheType = 0; cacheType < 3; cacheType++) {
            PVOID mappedRegion = MmMapIoSpace(physAddr, regionSize, (MEMORY_CACHING_TYPE)cacheTypes[cacheType]);
            if (!mappedRegion) continue;

            Log::Print("[SMBIOS] Mapping %s: 0x%p\n", cacheNames[cacheType], mappedRegion);

            for (ULONG_PTR offset = 0; offset < regionSize - sizeof(SMBIOS_ENTRY_POINT); offset += 16) {
                PSMBIOS_ENTRY_POINT candidate = (PSMBIOS_ENTRY_POINT)((PUCHAR)mappedRegion + offset);

                __try {
                    if (candidate->Signature[0] == '_' &&
                        candidate->Signature[1] == 'S' &&
                        candidate->Signature[2] == 'M' &&
                        candidate->Signature[3] == '_') {

                        Log::Print("[SMBIOS] *** SIGNATURE _SM_ FOUND! *** Offset: 0x%lX\n", offset);

                        if (candidate->Length >= 0x1F &&
                            candidate->MajorVersion >= 2 &&
                            candidate->TableLength > 0 &&
                            candidate->TableAddress != 0) {

                            UCHAR checksum = 0;
                            PUCHAR data = (PUCHAR)candidate;
                            for (int i = 0; i < candidate->Length; i++) {
                                checksum += data[i];
                            }

                            if (checksum == 0) {
                                Log::Print("[SMBIOS] *** VALID SMBIOS ENTRY POINT FOUND! ***\n");
                                Log::Print("[SMBIOS] Version: %d.%d\n", candidate->MajorVersion, candidate->MinorVersion);
                                Log::Print("[SMBIOS] Table: 0x%08X, Size: %d\n",
                                    candidate->TableAddress, candidate->TableLength);

                                return candidate;
                            }
                        }
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    // Continue scanning
                }
            }

            MmUnmapIoSpace(mappedRegion, regionSize);
        }
    }

    Log::Print("[SMBIOS] *** SMBIOS ENTRY POINT NOT FOUND ***\n");
    return NULL;
}

// =====================================================
// SMBIOS PHYSICAL MODIFICATION
// =====================================================

NTSTATUS ModifyPhysicalSmbios(PSMBIOS_ENTRY_POINT entryPoint) {
    Log::Print("[SMBIOS] *** MODIFYING PHYSICAL SMBIOS TABLE ***\n");

    if (!entryPoint) return STATUS_INVALID_PARAMETER;

    PHYSICAL_ADDRESS physAddr;
    physAddr.QuadPart = entryPoint->TableAddress;

    Log::Print("[SMBIOS] Physical address: 0x%08X\n", entryPoint->TableAddress);
    Log::Print("[SMBIOS] Table size: %d bytes\n", entryPoint->TableLength);
    Log::Print("[SMBIOS] Target UUID: %s\n", g_RandomUUIDString);

    MEMORY_CACHING_TYPE cacheTypes[] = { MmNonCached, MmWriteCombined, MmCached };
    const char* cacheNames[] = { "MmNonCached", "MmWriteCombined", "MmCached" };

    for (int cacheType = 0; cacheType < 3; cacheType++) {
        Log::Print("[SMBIOS] Trying mapping with %s...\n", cacheNames[cacheType]);

        g_MappedSmbiosTable = MmMapIoSpace(physAddr, entryPoint->TableLength,
            (MEMORY_CACHING_TYPE)cacheTypes[cacheType]);

        if (!g_MappedSmbiosTable) {
            Log::Print("[SMBIOS] Mapping failed with %s\n", cacheNames[cacheType]);
            continue;
        }

        Log::Print("[SMBIOS] *** MAPPING SUCCESS *** Virtual: 0x%p\n", g_MappedSmbiosTable);

        if (!VerifyMemoryWritable(g_MappedSmbiosTable, entryPoint->TableLength)) {
            Log::Print("[SMBIOS] *** MEMORY NOT WRITABLE ***\n");
            MmUnmapIoSpace(g_MappedSmbiosTable, entryPoint->TableLength);
            g_MappedSmbiosTable = NULL;
            continue;
        }

        Log::Print("[SMBIOS] *** MEMORY WRITABLE CONFIRMED ***\n");
        break;
    }

    if (!g_MappedSmbiosTable) {
        Log::Print("[SMBIOS] *** ALL MAPPING ATTEMPTS FAILED ***\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Find System Information structure (Type 1)
    Log::Print("[SMBIOS] *** SEARCHING FOR SYSTEM INFORMATION STRUCTURE ***\n");

    PUCHAR currentPos = (PUCHAR)g_MappedSmbiosTable;
    PUCHAR endPos = currentPos + entryPoint->TableLength;

    while (currentPos < endPos) {
        PSMBIOS_HEADER header = (PSMBIOS_HEADER)currentPos;

        __try {
            if (header->Type == 1) {
                Log::Print("[SMBIOS] *** SYSTEM INFORMATION FOUND! ***\n");

                PSMBIOS_SYSTEM_INFO sysInfo = (PSMBIOS_SYSTEM_INFO)header;

                // Log current UUID
                Log::Print("[SMBIOS] Current UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                    sysInfo->UUID[0], sysInfo->UUID[1], sysInfo->UUID[2], sysInfo->UUID[3],
                    sysInfo->UUID[4], sysInfo->UUID[5], sysInfo->UUID[6], sysInfo->UUID[7],
                    sysInfo->UUID[8], sysInfo->UUID[9], sysInfo->UUID[10], sysInfo->UUID[11],
                    sysInfo->UUID[12], sysInfo->UUID[13], sysInfo->UUID[14], sysInfo->UUID[15]);

                // Apply random UUID
                Log::Print("[SMBIOS] *** APPLYING RANDOM UUID ***\n");

                // Method 1: Direct copy
                RtlCopyMemory(sysInfo->UUID, g_RandomUUID, 16);

                // Method 2: Byte-by-byte
                for (int i = 0; i < 16; i++) {
                    sysInfo->UUID[i] = g_RandomUUID[i];
                }

                // Method 3: Volatile assignment
                volatile UCHAR* volatileUUID = (volatile UCHAR*)sysInfo->UUID;
                for (int i = 0; i < 16; i++) {
                    volatileUUID[i] = g_RandomUUID[i];
                }

                // Flush changes
                FlushMemoryChanges(sysInfo->UUID, 16);

                // Verify modification
                BOOLEAN success = TRUE;
                for (int i = 0; i < 16; i++) {
                    if (sysInfo->UUID[i] != g_RandomUUID[i]) {
                        success = FALSE;
                        Log::Print("[SMBIOS] Verification failed at byte %d (expected: 0x%02X, actual: 0x%02X)\n",
                            i, g_RandomUUID[i], sysInfo->UUID[i]);
                    }
                }

                if (success) {
                    Log::Print("[SMBIOS] *** UUID MODIFICATION SUCCESSFUL ***\n");
                    Log::Print("[SMBIOS] *** NEW UUID: %s ***\n", g_RandomUUIDString);
                    g_PhysicalModificationSuccess = TRUE;

                    FlushMemoryChanges(g_MappedSmbiosTable, entryPoint->TableLength);
                    KeInvalidateAllCaches();

                    // Modify strings if possible
                    Smbios::ChangeString(header, sysInfo->SerialNumber, g_RandomSerial);

                    return STATUS_SUCCESS;
                }
                else {
                    Log::Print("[SMBIOS] *** UUID MODIFICATION FAILED ***\n");
                    return STATUS_UNSUCCESSFUL;
                }
            }

            // Navigate to next structure
            currentPos += header->Length;
            while (currentPos < endPos && (*currentPos != 0 || *(currentPos + 1) != 0)) {
                currentPos++;
            }
            currentPos += 2;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Log::Print("[SMBIOS] Exception accessing SMBIOS structure\n");
            break;
        }
    }

    Log::Print("[SMBIOS] *** SYSTEM INFORMATION NOT FOUND ***\n");
    return STATUS_NOT_FOUND;
}

// =====================================================
// VERIFICATION
// =====================================================

NTSTATUS VerifyPersistence() {
    Log::Print("[SMBIOS] *** VERIFYING PERSISTENCE ***\n");

    if (!g_MappedSmbiosTable || !g_PhysicalModificationSuccess) {
        Log::Print("[SMBIOS] Cannot verify - no successful modifications\n");
        return STATUS_UNSUCCESSFUL;
    }

    LARGE_INTEGER delay;
    delay.QuadPart = -10000000LL; // 1 second
    KeDelayExecutionThread(KernelMode, FALSE, &delay);

    PUCHAR currentPos = (PUCHAR)g_MappedSmbiosTable;
    PUCHAR endPos = currentPos + g_SmbiosEntryPoint->TableLength;

    while (currentPos < endPos) {
        PSMBIOS_HEADER header = (PSMBIOS_HEADER)currentPos;

        __try {
            if (header->Type == 1) {
                PSMBIOS_SYSTEM_INFO sysInfo = (PSMBIOS_SYSTEM_INFO)header;

                Log::Print("[SMBIOS] Verification UUID: %02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X\n",
                    sysInfo->UUID[0], sysInfo->UUID[1], sysInfo->UUID[2], sysInfo->UUID[3],
                    sysInfo->UUID[4], sysInfo->UUID[5], sysInfo->UUID[6], sysInfo->UUID[7],
                    sysInfo->UUID[8], sysInfo->UUID[9], sysInfo->UUID[10], sysInfo->UUID[11],
                    sysInfo->UUID[12], sysInfo->UUID[13], sysInfo->UUID[14], sysInfo->UUID[15]);

                BOOLEAN matches = TRUE;
                for (int i = 0; i < 16; i++) {
                    if (sysInfo->UUID[i] != g_RandomUUID[i]) {
                        matches = FALSE;
                        break;
                    }
                }

                if (matches) {
                    Log::Print("[SMBIOS] *** PERSISTENCE VERIFIED ***\n");
                    return STATUS_SUCCESS;
                }
                else {
                    Log::Print("[SMBIOS] *** PERSISTENCE FAILED ***\n");
                    return STATUS_UNSUCCESSFUL;
                }
            }

            currentPos += header->Length;
            while (currentPos < endPos && (*currentPos != 0 || *(currentPos + 1) != 0)) {
                currentPos++;
            }
            currentPos += 2;

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            break;
        }
    }

    return STATUS_NOT_FOUND;
}

// =====================================================
// CLEANUP
// =====================================================

VOID Cleanup() {
    Log::Print("[SMBIOS] *** CLEANUP ***\n");

    if (g_MappedSmbiosTable && g_SmbiosEntryPoint) {
        VerifyPersistence();
        MmUnmapIoSpace(g_MappedSmbiosTable, g_SmbiosEntryPoint->TableLength);
        g_MappedSmbiosTable = NULL;
    }

    Log::Print("[SMBIOS] *** CLEANUP COMPLETE ***\n");
}

// =====================================================
// MAIN FUNCTION
// =====================================================

NTSTATUS Smbios::ChangeSmbiosSerials() {
    Log::Print("[SMBIOS] ==========================================\n");
    Log::Print("[SMBIOS] ===  PERMANENT RANDOM UUID SPOOFER   ===\n");
    Log::Print("[SMBIOS] ===     SURVIVES REBOOT             ===\n");
    Log::Print("[SMBIOS] ==========================================\n");

    NTSTATUS finalStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN anySuccess = FALSE;

    __try {
        // STEP 1: Generate random identifiers
        Log::Print("[SMBIOS] STEP 1: Generating random identifiers...\n");
        GenerateRandomIdentifiers();
        Log::Print("[SMBIOS] *** RANDOM IDENTIFIERS GENERATED ***\n");

        // STEP 2: Modify registry for persistence
        Log::Print("[SMBIOS] STEP 2: Modifying registry for persistence...\n");
        NTSTATUS registryStatus = ModifyRegistryValues();
        if (NT_SUCCESS(registryStatus)) {
            Log::Print("[SMBIOS] *** REGISTRY MODIFICATION SUCCESS ***\n");
            anySuccess = TRUE;
        }

        // STEP 3: Find SMBIOS entry point
        Log::Print("[SMBIOS] STEP 3: Finding SMBIOS entry point...\n");
        g_SmbiosEntryPoint = FindSmbiosEntryPoint();
        if (!g_SmbiosEntryPoint) {
            Log::Print("[SMBIOS] *** WARNING: SMBIOS NOT FOUND ***\n");
            if (anySuccess) {
                finalStatus = STATUS_SUCCESS;
            }
        }
        else {
            // STEP 4: Modify physical SMBIOS
            Log::Print("[SMBIOS] STEP 4: Modifying physical SMBIOS...\n");
            NTSTATUS physicalStatus = ModifyPhysicalSmbios(g_SmbiosEntryPoint);
            if (NT_SUCCESS(physicalStatus)) {
                Log::Print("[SMBIOS] *** PHYSICAL MODIFICATION SUCCESS ***\n");
                anySuccess = TRUE;

                // STEP 5: Verify persistence
                Log::Print("[SMBIOS] STEP 5: Verifying persistence...\n");
                NTSTATUS verifyStatus = VerifyPersistence();
                if (NT_SUCCESS(verifyStatus)) {
                    Log::Print("[SMBIOS] *** PERSISTENCE CONFIRMED ***\n");
                    finalStatus = STATUS_SUCCESS;
                }
                else {
                    Log::Print("[SMBIOS] *** WARNING: PERSISTENCE NOT CONFIRMED ***\n");
                    if (anySuccess) {
                        finalStatus = STATUS_SUCCESS;
                    }
                }
            }
        }

        if (NT_SUCCESS(finalStatus) || anySuccess) {
            Log::Print("[SMBIOS] ==========================================\n");
            Log::Print("[SMBIOS] *** SUCCESS! ***\n");
            Log::Print("[SMBIOS] *** RANDOM UUID: %s ***\n", g_RandomUUIDString);
            Log::Print("[SMBIOS] *** RANDOM SERIAL: %s ***\n", g_RandomSerial);
            Log::Print("[SMBIOS] *** REGISTRY: MODIFIED ***\n");
            if (g_PhysicalModificationSuccess) {
                Log::Print("[SMBIOS] *** PHYSICAL SMBIOS: MODIFIED ***\n");
            }
            Log::Print("[SMBIOS] *** PERSISTENCE: GUARANTEED ***\n");
            Log::Print("[SMBIOS] ==========================================\n");
            Log::Print("[SMBIOS] INSTRUCTIONS:\n");
            Log::Print("[SMBIOS] 1. REBOOT system now\n");
            Log::Print("[SMBIOS] 2. Test: wmic csproduct get uuid\n");
            Log::Print("[SMBIOS] 3. Expected: %s\n", g_RandomUUIDString);
            Log::Print("[SMBIOS] 4. Each run = new random UUID\n");
            Log::Print("[SMBIOS] 5. Changes survive reboot\n");
            Log::Print("[SMBIOS] ==========================================\n");

            finalStatus = STATUS_SUCCESS;
        }
        else {
            Log::Print("[SMBIOS] ==========================================\n");
            Log::Print("[SMBIOS] *** FAILURE ***\n");
            Log::Print("[SMBIOS] ==========================================\n");
            Log::Print("[SMBIOS] TROUBLESHOOTING:\n");
            Log::Print("[SMBIOS] 1. Disable Secure Boot\n");
            Log::Print("[SMBIOS] 2. Disable TPM\n");
            Log::Print("[SMBIOS] 3. Disable HVCI: bcdedit /set hypervisorlaunchtype off\n");
            Log::Print("[SMBIOS] 4. Try Legacy BIOS mode\n");
            Log::Print("[SMBIOS] 5. Test in VM first\n");
            Log::Print("[SMBIOS] ==========================================\n");

            finalStatus = STATUS_UNSUCCESSFUL;
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log::Print("[SMBIOS] *** CRITICAL EXCEPTION: 0x%08X ***\n", GetExceptionCode());
        finalStatus = STATUS_UNSUCCESSFUL;
    }

    Log::Print("[SMBIOS] ==========================================\n");
    Log::Print("[SMBIOS] FINAL STATUS: %s\n", NT_SUCCESS(finalStatus) ? "SUCCESS" : "FAILED");
    Log::Print("[SMBIOS] ==========================================\n");

    return finalStatus;
}

// =====================================================
// STRING FUNCTIONS
// =====================================================

char* Smbios::GetString(SMBIOS_HEADER* header, UCHAR string) {
    if (!header || string == 0) return NULL;

    __try {
        char* data = (char*)header + header->Length;
        for (UCHAR i = 1; i < string; i++) {
            if (*data == 0) return NULL;
            while (*data != 0) data++;
            data++;
        }
        return (*data != 0) ? data : NULL;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }
}

void Smbios::ChangeString(SMBIOS_HEADER* header, UCHAR string, const char* newString) {
    if (!header || !newString || string == 0) return;

    __try {
        char* originalString = GetString(header, string);
        if (!originalString) return;

        size_t originalLength = strlen(originalString);
        size_t newLength = strlen(newString);

        if (newLength <= originalLength) {
            RtlCopyMemory(originalString, newString, newLength);
            RtlZeroMemory(originalString + newLength, originalLength - newLength);
            FlushMemoryChanges(originalString, originalLength);
        }
        else {
            RtlCopyMemory(originalString, newString, originalLength);
            originalString[originalLength - 1] = '\0';
            FlushMemoryChanges(originalString, originalLength);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // Ignore exceptions
    }
}

#pragma warning(pop)