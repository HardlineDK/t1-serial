#pragma warning(push)
#pragma warning(disable: 4996)
#pragma warning(disable: 4267)
#pragma warning(disable: 4244)
#pragma warning(disable: 4189)
#pragma warning(disable: 4005)

#include <ntifs.h>
#include <ntimage.h>
#include "shared.h"
#include "utils.h"
#include "log.h"

// Declare external kernel functions
extern "C" {
    NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
        IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
        OUT PVOID SystemInformation,
        IN ULONG SystemInformationLength,
        OUT PULONG ReturnLength OPTIONAL
    );
}

/**
 * \brief Get base address of kernel module
 * \param moduleName Name of the module (ex. storport.sys)
 * \return Address of the module or null pointer if failed
 */
PVOID Utils::GetModuleBase(const char* moduleName)
{
    if (!moduleName)
        return nullptr;

    PVOID address = nullptr;
    ULONG size = 0;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return nullptr;

    PSYSTEM_MODULE_INFORMATION moduleList =
        (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, size, POOL_TAG);
    if (!moduleList)
        return nullptr;

    status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
    if (!NT_SUCCESS(status))
        goto cleanup;

    for (ULONG i = 0; i < moduleList->ulModuleCount; i++)
    {
        SYSTEM_MODULE_ENTRY module = moduleList->Modules[i];
        if (strstr((char*)module.ImageName, moduleName))
        {
            address = module.Base;
            break;
        }
    }

cleanup:
    ExFreePoolWithTag(moduleList, POOL_TAG);
    return address;
}

/**
 * \brief Checks if buffer matches pattern and mask
 */
bool Utils::CheckMask(const char* base, const char* pattern, const char* mask)
{
    if (!base || !pattern || !mask)
        return false;

    for (; *mask; ++base, ++pattern, ++mask)
    {
        if ('x' == *mask && *base != *pattern)
        {
            return false;
        }
    }
    return true;
}

/**
 * \brief Find byte pattern in given buffer
 */
PVOID Utils::FindPattern(PVOID base, int length, const char* pattern, const char* mask)
{
    if (!base || !pattern || !mask || length <= 0)
        return nullptr;

    int maskLength = (int)strlen(mask);
    length -= maskLength;

    for (int i = 0; i <= length; ++i)
    {
        char* data = (char*)base;
        char* address = &data[i];
        if (CheckMask(address, pattern, mask))
            return (PVOID)address;
    }
    return nullptr;
}

/**
 * \brief Find byte pattern in module sections
 */
PVOID Utils::FindPatternImage(PVOID base, const char* pattern, const char* mask)
{
    if (!base || !pattern || !mask)
        return nullptr;

    PVOID match = nullptr;

    __try
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)((char*)base + dosHeader->e_lfanew);
        if (headers->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);

        for (int i = 0; i < headers->FileHeader.NumberOfSections; ++i)
        {
            PIMAGE_SECTION_HEADER section = &sections[i];

            if (memcmp(section->Name, ".text", 5) == 0 ||
                memcmp(section->Name, "PAGE", 4) == 0)
            {
                match = FindPattern(
                    (char*)base + section->VirtualAddress,
                    section->Misc.VirtualSize,
                    pattern,
                    mask);
                if (match)
                    break;
            }
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        Log::Print("Exception in FindPatternImage\n");
        return nullptr;
    }

    return match;
}

/**
 * \brief Generate pseudo-random text
 */
void Utils::RandomText(char* text, const int length)
{
    if (!text || length <= 0)
        return;

    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    ULONG seed = KeQueryTimeIncrement();

    for (int n = 0; n < length; n++)
    {
        ULONG key = RtlRandomEx(&seed) % (sizeof(alphanum) - 1);
        text[n] = alphanum[key];
    }

    text[length] = '\0';
}

#pragma warning(pop)