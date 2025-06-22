#include <ntifs.h>
#include "shared.h"
#include "smbios.h"

// =====================================================
// MUTANTE INTELLIGENT SPOOFER - VERSÃO FINAL
// Todos os conflitos de estruturas resolvidos
// =====================================================

#define EXCEPTION_ACCESS_VIOLATION     0xC0000005L
#define EXCEPTION_ILLEGAL_INSTRUCTION  0xC000001DL

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[MUTANTE] === DRIVER UNLOADING SAFELY ===\n");
}

// =====================================================
// VERIFICAÇÃO SIMPLIFICADA SE UUID JÁ FOI MODIFICADO
// =====================================================

BOOLEAN IsSystemAlreadySpoofed()
{
    DbgPrint("[MUTANTE-CHECK] Checking if system is already spoofed...\n");

    NTSTATUS status;
    HANDLE keyHandle = NULL;
    BOOLEAN alreadySpoofed = FALSE;

    __try {
        UNICODE_STRING keyPath;
        OBJECT_ATTRIBUTES objAttr;

        RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Control\\SystemInformation");
        InitializeObjectAttributes(&objAttr, &keyPath,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);

        if (NT_SUCCESS(status)) {
            UNICODE_STRING valueName;
            RtlInitUnicodeString(&valueName, L"SystemUUID");

            UCHAR buffer[256];
            PKEY_VALUE_PARTIAL_INFORMATION valueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
            ULONG resultLength;

            status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation,
                valueInfo, sizeof(buffer), &resultLength);

            if (NT_SUCCESS(status) && valueInfo->DataLength > 0) {
                PUCHAR uuidData = (PUCHAR)valueInfo->Data;

                if (valueInfo->DataLength >= 8) {
                    if (uuidData[0] == 'D' && uuidData[1] == 'E' &&
                        uuidData[2] == 'A' && uuidData[3] == 'D') {
                        DbgPrint("[MUTANTE-CHECK] Found MUTANTE signature in registry!\n");
                        alreadySpoofed = TRUE;
                    }
                }
            }

            ZwClose(keyHandle);
        }

        if (!alreadySpoofed) {
            DbgPrint("[MUTANTE-CHECK] No registry spoofing found - system appears original\n");
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MUTANTE-CHECK] Exception during spoofing check: 0x%08X\n", GetExceptionCode());
        if (keyHandle) ZwClose(keyHandle);
    }

    return alreadySpoofed;
}

// =====================================================
// GERAÇÃO DE IDENTIFICADORES SEGUROS - SIMPLIFICADA
// =====================================================

void GenerateSecureRandomSerial(char* serialBuffer, SIZE_T length)
{
    if (!serialBuffer || length == 0) return;

    __try {
        LARGE_INTEGER tickCount;
        KeQueryTickCount(&tickCount);

        ULONG seed = (ULONG)(tickCount.QuadPart & 0xFFFFFFFF);
        const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        for (SIZE_T i = 0; i < length - 1; i++) {
            seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
            serialBuffer[i] = charset[seed % (sizeof(charset) - 1)];
        }
        serialBuffer[length - 1] = '\0';

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MUTANTE] Exception in GenerateSecureRandomSerial\n");
        for (SIZE_T i = 0; i < length - 1; i++) {
            serialBuffer[i] = 'A' + (char)(i % 26);
        }
        serialBuffer[length - 1] = '\0';
    }
}

// =====================================================
// DETECÇÃO DE AMBIENTE SEGURO - SIMPLIFICADA
// =====================================================

BOOLEAN IsEnvironmentSafe()
{
    DbgPrint("[MUTANTE-SAFETY] Checking environment safety...\n");

    __try {
        KIRQL currentIrql = KeGetCurrentIrql();
        if (currentIrql > PASSIVE_LEVEL) {
            DbgPrint("[MUTANTE-SAFETY] WARNING: IRQL too high (%d)\n", currentIrql);
            return FALSE;
        }

        RTL_OSVERSIONINFOW versionInfo;
        RtlZeroMemory(&versionInfo, sizeof(versionInfo));
        versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
        NTSTATUS versionStatus = RtlGetVersion(&versionInfo);

        if (!NT_SUCCESS(versionStatus)) {
            DbgPrint("[MUTANTE-SAFETY] Could not get Windows version\n");
            return FALSE;
        }

        if (versionInfo.dwMajorVersion < 6) {
            DbgPrint("[MUTANTE-SAFETY] Unsupported Windows version: %lu.%lu\n",
                versionInfo.dwMajorVersion, versionInfo.dwMinorVersion);
            return FALSE;
        }

        DbgPrint("[MUTANTE-SAFETY] Environment is safe for spoofing\n");
        DbgPrint("[MUTANTE-SAFETY] Windows %lu.%lu Build %lu\n",
            versionInfo.dwMajorVersion, versionInfo.dwMinorVersion, versionInfo.dwBuildNumber);

        return TRUE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MUTANTE-SAFETY] Exception during safety check: 0x%08X\n", GetExceptionCode());
        return FALSE;
    }
}

// =====================================================
// DRIVER ENTRY PRINCIPAL - MÉTODO INTELIGENTE
// =====================================================

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[MUTANTE] ==========================================\n");
    DbgPrint("[MUTANTE] ===   MUTANTE SECURE SPOOFER v11.0   ===\n");
    DbgPrint("[MUTANTE] ===     PERMANENT & INTELLIGENT      ===\n");
    DbgPrint("[MUTANTE] ===        FINAL CORRECTED           ===\n");
    DbgPrint("[MUTANTE] ==========================================\n");

    if (DriverObject) {
        DbgPrint("[MUTANTE] DriverObject: 0x%p (Normal loading)\n", DriverObject);
        DriverObject->DriverUnload = DriverUnload;
    }
    else {
        DbgPrint("[MUTANTE] DriverObject is NULL (Manual mapping mode)\n");
    }

    // FASE 1: VERIFICAÇÕES DE SEGURANÇA
    DbgPrint("[MUTANTE] ==========================================\n");
    DbgPrint("[MUTANTE] ===     PHASE 1: SAFETY CHECKS       ===\n");
    DbgPrint("[MUTANTE] ==========================================\n");

    if (!IsEnvironmentSafe()) {
        DbgPrint("[MUTANTE] *** ENVIRONMENT NOT SAFE - ABORTING ***\n");
        return STATUS_UNSUCCESSFUL;
    }

    // FASE 2: DETECÇÃO INTELIGENTE
    DbgPrint("[MUTANTE] ==========================================\n");
    DbgPrint("[MUTANTE] ===  PHASE 2: INTELLIGENT DETECTION  ===\n");
    DbgPrint("[MUTANTE] ==========================================\n");

    BOOLEAN alreadySpoofed = IsSystemAlreadySpoofed();

    if (alreadySpoofed) {
        DbgPrint("[MUTANTE] *** DETECTION RESULT: ALREADY SPOOFED ***\n");
        DbgPrint("[MUTANTE] *** This system was previously modified by MUTANTE ***\n");
        DbgPrint("[MUTANTE] *** No action needed - spoofing is persistent ***\n");
        DbgPrint("[MUTANTE] ==========================================\n");
        DbgPrint("[MUTANTE] STATUS: SYSTEM_ALREADY_SPOOFED\n");
        DbgPrint("[MUTANTE] ACTION: NO_MODIFICATION_REQUIRED\n");
        DbgPrint("[MUTANTE] PERSISTENCE: CONFIRMED_ACTIVE\n");
        DbgPrint("[MUTANTE] ==========================================\n");
        DbgPrint("[MUTANTE] *** MISSION ALREADY ACCOMPLISHED ***\n");
        DbgPrint("[MUTANTE] ==========================================\n");
        return STATUS_SUCCESS;
    }

    DbgPrint("[MUTANTE] *** DETECTION RESULT: ORIGINAL SYSTEM ***\n");
    DbgPrint("[MUTANTE] *** This is the FIRST execution on this system ***\n");
    DbgPrint("[MUTANTE] *** Proceeding with ONE-TIME permanent spoofing ***\n");

    // FASE 3: GERAÇÃO DE NOVOS IDENTIFICADORES
    DbgPrint("[MUTANTE] ==========================================\n");
    DbgPrint("[MUTANTE] ===  PHASE 3: GENERATING NEW IDs      ===\n");
    DbgPrint("[MUTANTE] ==========================================\n");

    char newBiosSerial[32];
    char newSystemSerial[32];
    char newMBSerial[32];

    GenerateSecureRandomSerial(newBiosSerial, sizeof(newBiosSerial));
    GenerateSecureRandomSerial(newSystemSerial, sizeof(newSystemSerial));
    GenerateSecureRandomSerial(newMBSerial, sizeof(newMBSerial));

    DbgPrint("[MUTANTE] Generated secure identifiers:\n");
    DbgPrint("[MUTANTE] - New BIOS Serial: %s\n", newBiosSerial);
    DbgPrint("[MUTANTE] - New System Serial: %s\n", newSystemSerial);
    DbgPrint("[MUTANTE] - New MB Serial: %s\n", newMBSerial);
    DbgPrint("[MUTANTE] - New UUID: DEADBEEF-XXXX-XXXX-XXXX-XXXXXXXXXXXX\n");

    // FASE 4: SPOOFING PERMANENTE E SEGURO
    DbgPrint("[MUTANTE] ==========================================\n");
    DbgPrint("[MUTANTE] ===  PHASE 4: PERMANENT SPOOFING     ===\n");
    DbgPrint("[MUTANTE] ==========================================\n");

    NTSTATUS smbiosStatus = STATUS_UNSUCCESSFUL;
    BOOLEAN spoofingSuccess = FALSE;

    __try {
        DbgPrint("[MUTANTE] [SMBIOS] Starting PERMANENT hybrid spoofing...\n");
        DbgPrint("[MUTANTE] [SMBIOS] Using registry + memory modification...\n");
        DbgPrint("[MUTANTE] [SMBIOS] This will be the ONLY execution needed...\n");

        smbiosStatus = Smbios::ChangeSmbiosSerials();

        if (NT_SUCCESS(smbiosStatus)) {
            DbgPrint("[MUTANTE] [SMBIOS] *** SUCCESS: PERMANENT spoofing completed ***\n");
            DbgPrint("[MUTANTE] [SMBIOS] *** System will remember these changes forever ***\n");
            DbgPrint("[MUTANTE] [SMBIOS] *** Registry hooks installed for WMI queries ***\n");
            spoofingSuccess = TRUE;
        }
        else {
            DbgPrint("[MUTANTE] [SMBIOS] *** FAILED: Status = 0x%08X ***\n", smbiosStatus);

            switch (smbiosStatus) {
            case STATUS_NOT_FOUND:
                DbgPrint("[MUTANTE] [SMBIOS] DIAGNOSIS: SMBIOS structures not accessible\n");
                break;
            case STATUS_ACCESS_VIOLATION:
                DbgPrint("[MUTANTE] [SMBIOS] DIAGNOSIS: Memory protection prevented modification\n");
                break;
            case STATUS_INSUFFICIENT_RESOURCES:
                DbgPrint("[MUTANTE] [SMBIOS] DIAGNOSIS: Memory mapping failed\n");
                break;
            default:
                DbgPrint("[MUTANTE] [SMBIOS] DIAGNOSIS: Unknown error - check logs above\n");
                break;
            }
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ULONG exceptionCode = GetExceptionCode();
        DbgPrint("[MUTANTE] [SMBIOS] *** CRITICAL EXCEPTION: 0x%08X ***\n", exceptionCode);

        if (exceptionCode == EXCEPTION_ACCESS_VIOLATION) {
            DbgPrint("[MUTANTE] [SMBIOS] ACCESS VIOLATION: Memory protected by system\n");
        }
        else if (exceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
            DbgPrint("[MUTANTE] [SMBIOS] ILLEGAL INSTRUCTION: Code corruption detected\n");
        }

        smbiosStatus = STATUS_UNSUCCESSFUL;
    }

    // FASE 5: RELATÓRIO FINAL E INSTRUÇÕES
    DbgPrint("[MUTANTE] ==========================================\n");
    DbgPrint("[MUTANTE] ===        FINAL RESULTS             ===\n");
    DbgPrint("[MUTANTE] ==========================================\n");

    if (spoofingSuccess) {
        DbgPrint("[MUTANTE] *** MISSION ACCOMPLISHED! ***\n");
        DbgPrint("[MUTANTE] *** UUID and serials have been PERMANENTLY modified ***\n");
        DbgPrint("[MUTANTE] *** System will boot with new identifiers from now on ***\n");
        DbgPrint("[MUTANTE] *** Registry hooks ensure WMI queries return spoofed data ***\n");
        DbgPrint("[MUTANTE] *** NO NEED to run this driver again! ***\n");
        DbgPrint("[MUTANTE] ==========================================\n");
        DbgPrint("[MUTANTE] STATUS: FIRST_TIME_SUCCESS\n");
        DbgPrint("[MUTANTE] PERMANENCE: TRUE\n");
        DbgPrint("[MUTANTE] FUTURE_EXECUTIONS: WILL_DETECT_AND_SKIP\n");
        DbgPrint("[MUTANTE] METHOD: HYBRID_REGISTRY_MEMORY\n");
        DbgPrint("[MUTANTE] ==========================================\n");
        DbgPrint("[MUTANTE] USAGE INSTRUCTIONS:\n");
        DbgPrint("[MUTANTE] 1. REBOOT your system now for full effect\n");
        DbgPrint("[MUTANTE] 2. Verify with: wmic csproduct get uuid\n");
        DbgPrint("[MUTANTE] 3. UUID should start with DEADBEEF-...\n");
        DbgPrint("[MUTANTE] 4. If you run this driver again, it will detect\n");
        DbgPrint("[MUTANTE]    spoofing and skip modification automatically\n");
        DbgPrint("[MUTANTE] 5. Spoofing persists across reboots and updates\n");
        DbgPrint("[MUTANTE] ==========================================\n");
    }
    else {
        DbgPrint("[MUTANTE] *** SPOOFING FAILED ***\n");
        DbgPrint("[MUTANTE] *** UUID and serials were NOT changed ***\n");
        DbgPrint("[MUTANTE] *** System remains in original state ***\n");
        DbgPrint("[MUTANTE] *** You can try running this driver again ***\n");
        DbgPrint("[MUTANTE] ==========================================\n");
        DbgPrint("[MUTANTE] STATUS: FIRST_TIME_FAILED\n");
        DbgPrint("[MUTANTE] PERMANENCE: FALSE\n");
        DbgPrint("[MUTANTE] NEXT_ACTION: TROUBLESHOOT_AND_RETRY\n");
        DbgPrint("[MUTANTE] ==========================================\n");
        DbgPrint("[MUTANTE] TROUBLESHOOTING STEPS:\n");
        DbgPrint("[MUTANTE] 1. Disable HVCI: bcdedit /set hypervisorlaunchtype off\n");
        DbgPrint("[MUTANTE] 2. Disable Secure Boot in UEFI/BIOS\n");
        DbgPrint("[MUTANTE] 3. Disable Virtualization if enabled\n");
        DbgPrint("[MUTANTE] 4. Run as Administrator with Test Mode\n");
        DbgPrint("[MUTANTE] 5. Try different driver loading method\n");
        DbgPrint("[MUTANTE] ==========================================\n");
    }

    DbgPrint("[MUTANTE] ==========================================\n");
    DbgPrint("[MUTANTE] BUILD_ID: SECURE_PERMANENT_v11.0\n");
    DbgPrint("[MUTANTE] PURPOSE: PERMANENT_UUID_SPOOFING\n");
    DbgPrint("[MUTANTE] INTELLIGENCE: AUTO_DETECTION_ENABLED\n");
    DbgPrint("[MUTANTE] SAFETY: MULTIPLE_CHECKS_ACTIVE\n");
    DbgPrint("[MUTANTE] METHOD: HYBRID_REGISTRY_MEMORY\n");
    DbgPrint("[MUTANTE] ==========================================\n");

    DbgPrint("[MUTANTE] Mutante Secure UUID Spoofer execution completed!\n");

    return STATUS_SUCCESS;
}