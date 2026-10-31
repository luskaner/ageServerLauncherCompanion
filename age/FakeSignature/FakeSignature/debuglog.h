// AoEIntegrityBypass — Debug logging header
// Consistente con los otros DLL de ageLANServerLauncherCompanion

#pragma once

#include <windows.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

// Abre el fichero de log junto al DLL
void DebugLogOpen(HMODULE hModule);

// Escribe una línea de log (formato printf)
void __cdecl DebugLog(const char* fmt, ...);

// Cierra el fichero de log
void DebugLogClose(void);

#ifdef __cplusplus
}
#endif
