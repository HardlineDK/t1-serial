#pragma once
#include "shared.h"

// =====================================================
// SMBIOS SPOOFER - HEADER CORRIGIDO E SEGURO
// Remove conflitos e redefinições, mantém compatibilidade
// =====================================================

namespace Smbios
{
    // Funções originais mantidas para compatibilidade
    char* GetString(SMBIOS_HEADER* header, UCHAR string);
    void ChangeString(SMBIOS_HEADER* header, UCHAR string, const char* newString);

    // Função principal - modifica UUID e outros seriais SMBIOS
    NTSTATUS ChangeSmbiosSerials();
}