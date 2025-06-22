#include "log.h"
#include <stdarg.h>

void Log::Print(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    char buffer[512];
    NTSTATUS status = RtlStringCbVPrintfA(buffer, sizeof(buffer), format, args);
    if (NT_SUCCESS(status))
    {
        // Remover prefixo [MUTANTE] para logs limpos
        KdPrint(("%s", buffer)); // <-- SEM prefixo automático
    }
    va_end(args);
}