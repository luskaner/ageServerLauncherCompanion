// AoEIntegrityBypass — Debug logging implementation
// Consistente con los otros DLL de ageLANServerLauncherCompanion

#include "pch.h"
#include "debuglog.h"

static FILE* g_logFile = nullptr;

void DebugLogOpen(HMODULE hModule)
{
    if (g_logFile) return;

    char path[MAX_PATH];
    GetModuleFileNameA(hModule, path, MAX_PATH);
    char* dot = strrchr(path, '.');
    if (dot) strcpy_s(dot, MAX_PATH - (dot - path), ".log");
    else strcat_s(path, MAX_PATH, ".log");

    errno_t err = fopen_s(&g_logFile, path, "a");
    if (err != 0 || !g_logFile) {
        g_logFile = nullptr;
        return;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logFile, "\n=== AoEIntegrityBypass %04d-%02d-%02d %02d:%02d:%02d ===\n",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    fflush(g_logFile);
}

void __cdecl DebugLog(const char* fmt, ...)
{
    if (!g_logFile) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_logFile, "[%02d:%02d:%02d.%03hu] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_logFile, fmt, args);
    va_end(args);

    fflush(g_logFile);
}

void DebugLogClose(void)
{
    if (g_logFile) {
        fprintf(g_logFile, "=== AoEIntegrityBypass descargado ===\n");
        fclose(g_logFile);
        g_logFile = nullptr;
    }
}
