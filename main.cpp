#include <ntifs.h>
#include "shared.h"
#include "smbios.h"

// =====================================================
// CLEAN MAIN DRIVER - RANDOM UUID VERSION
// =====================================================

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("[MAIN] === DRIVER UNLOADING SAFELY ===\n");
}

BOOLEAN IsEnvironmentSafe()
{
    DbgPrint("[MAIN] Checking environment safety...\n");

    __try {
        KIRQL currentIrql = KeGetCurrentIrql();
        if (currentIrql > PASSIVE_LEVEL) {
            DbgPrint("[MAIN] WARNING: IRQL too high (%d)\n", currentIrql);
            return FALSE;
        }

        RTL_OSVERSIONINFOW versionInfo;
        RtlZeroMemory(&versionInfo, sizeof(versionInfo));
        versionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
        NTSTATUS versionStatus = RtlGetVersion(&versionInfo);

        if (!NT_SUCCESS(versionStatus)) {
            DbgPrint("[MAIN] Could not get Windows version\n");
            return FALSE;
        }

        if (versionInfo.dwMajorVersion < 6) {
            DbgPrint("[MAIN] Unsupported Windows version: %lu.%lu\n",
                versionInfo.dwMajorVersion, versionInfo.dwMinorVersion);
            return FALSE;
        }

        DbgPrint("[MAIN] Environment is safe for spoofing\n");
        DbgPrint("[MAIN] Windows %lu.%lu Build %lu\n",
            versionInfo.dwMajorVersion, versionInfo.dwMinorVersion, versionInfo.dwBuildNumber);

        return TRUE;

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgPrint("[MAIN] Exception during safety check: 0x%08X\n", GetExceptionCode());
        return FALSE;
    }
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrint("[MAIN] ==========================================\n");
    DbgPrint("[MAIN] ===   RANDOM UUID SPOOFER v12.0      ===\n");
    DbgPrint("[MAIN] ===     NEW RANDOM UUID EACH TIME    ===\n");
    DbgPrint("[MAIN] ===       SURVIVES REBOOT            ===\n");
    DbgPrint("[MAIN] ==========================================\n");

    if (DriverObject) {
        DbgPrint("[MAIN] DriverObject: 0x%p (Normal loading)\n", DriverObject);
        DriverObject->DriverUnload = DriverUnload;
    }
    else {
        DbgPrint("[MAIN] DriverObject is NULL (Manual mapping mode)\n");
    }

    // Safety check
    DbgPrint("[MAIN] ==========================================\n");
    DbgPrint("[MAIN] ===     SAFETY CHECKS               ===\n");
    DbgPrint("[MAIN] ==========================================\n");

    if (!IsEnvironmentSafe()) {
        DbgPrint("[MAIN] *** ENVIRONMENT NOT SAFE - ABORTING ***\n");
        return STATUS_UNSUCCESSFUL;
    }

    // Execute SMBIOS spoofing
    DbgPrint("[MAIN] ==========================================\n");
    DbgPrint("[MAIN] ===     EXECUTING SMBIOS SPOOFING   ===\n");
    DbgPrint("[MAIN] ==========================================\n");

    NTSTATUS smbiosStatus = STATUS_UNSUCCESSFUL;

    __try {
        DbgPrint("[MAIN] Calling SMBIOS spoofing function...\n");

        smbiosStatus = Smbios::ChangeSmbiosSerials();

        if (NT_SUCCESS(smbiosStatus)) {
            DbgPrint("[MAIN] *** SMBIOS SPOOFING SUCCESS ***\n");
        }
        else {
            DbgPrint("[MAIN] *** SMBIOS SPOOFING FAILED: 0x%08X ***\n", smbiosStatus);
        }

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        ULONG exceptionCode = GetExceptionCode();
        DbgPrint("[MAIN] *** CRITICAL EXCEPTION: 0x%08X ***\n", exceptionCode);
        smbiosStatus = STATUS_UNSUCCESSFUL;
    }

    // Final report
    DbgPrint("[MAIN] ==========================================\n");
    DbgPrint("[MAIN] ===        FINAL RESULTS             ===\n");
    DbgPrint("[MAIN] ==========================================\n");

    if (NT_SUCCESS(smbiosStatus)) {
        DbgPrint("[MAIN] *** DRIVER EXECUTION SUCCESS ***\n");
        DbgPrint("[MAIN] *** Random UUID has been applied ***\n");
        DbgPrint("[MAIN] *** Check SMBIOS logs above for details ***\n");
        DbgPrint("[MAIN] *** Reboot to verify persistence ***\n");
    }
    else {
        DbgPrint("[MAIN] *** DRIVER EXECUTION FAILED ***\n");
        DbgPrint("[MAIN] *** Check troubleshooting steps above ***\n");
    }

    DbgPrint("[MAIN] ==========================================\n");
    DbgPrint("[MAIN] Driver execution completed!\n");

    return STATUS_SUCCESS;
}