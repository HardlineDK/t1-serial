#pragma once
#include "shared.h"

namespace Disks
{
    void DisableSmartBit(PRAID_UNIT_EXTENSION extension);
    PDEVICE_OBJECT GetRaidDevice(const wchar_t* deviceName);
    NTSTATUS DiskLoop(PDEVICE_OBJECT deviceArray, RaidUnitRegisterInterfaces registerInterfaces);
    NTSTATUS ChangeDiskSerials();
    NTSTATUS DisableSmart();
}