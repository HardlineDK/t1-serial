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
        KdPrint(("[MUTANTE] %s", buffer));
    }

    va_end(args);
}