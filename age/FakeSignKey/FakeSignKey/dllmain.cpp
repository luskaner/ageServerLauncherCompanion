// FakeSignKey — Sustitución flexible y exacta de la clave pública (multi-age)
//
// Busca AUTOMÁTICAMENTE en memoria la clave RSA-2048 embebida (SPKI PKCS#1,
// 294 bytes) por su patrón DER y la identifica de forma EXACTA comparando su
// SHA-256 con el hash conocido de la clave original de RelicLink. No depende
// de un RVA hardcodeado ni de variables de entorno para la dirección. Funciona
// en distintas compilaciones de AoE2DE_s.exe (y otros juegos de la franquicia
// como AoE3DE, AoMRT y AoE4) donde el RVA puede cambiar.
//
// Sustituye los 294 bytes encontrados por la clave pública del servidor
// comunitario (sigkey.der), sin desactivar la comprobación de firma y sin
// modificar .text ni la cabecera PE.
//
// La ruta al fichero sigkey.der se recibe ÚNICAMENTE como parámetro de línea
// de comandos del proceso (--sigkey-der <ruta> o /sigkey-der:<ruta>). No hay
// valor por defecto (ni junto al DLL, ni por variable de entorno).
//
// Compilar con: cl.exe /nologo /LD /O2 /DWIN32 /D_WINDOWS /W3 /D_CRT_SECURE_NO_WARNINGS dllmain.cpp /link /OUT:AgeFakeSignKey.dll

#include "pch.h"
#include "framework.h"
#include "debuglog.h"

// Patrón SPKI PKCS#1 para RSA-2048 (DER):
// SEQUENCE { SEQUENCE { OID rsaEncryption, NULL }, BIT STRING { ... } }
static const BYTE SPKI_PATTERN[] = {
    0x30, 0x82, 0x01, 0x22,   // SEQUENCE, longitud 0x0122
    0x30, 0x0D,               // SEQUENCE, longitud 13
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,  // OID 1.2.840.113549.1.1.1
    0x05, 0x00,               // NULL
    0x03, 0x82, 0x01, 0x0F, 0x00  // BIT STRING, longitud 0x010F, unused bits 0
};
static const size_t PATTERN_SIZE = sizeof(SPKI_PATTERN);

// SHA-256 conocido de la clave pública RSA-2048 embebida originalmente en el
// cliente (misma en AoE1DE, AoE2DE, AoE3DE, AoMRT y AoE4). Se usa para
// identificar el bloque exacto sin riesgo de falsos positivos.
static const char ORIGINAL_KEY_SHA256_HEX[] =
    "1cb03454e1083642d92914fdddb3cef8efad79cebec4e721a179b90177c3334d";

static const size_t KEY_SIZE = 294;

// ---------------------------------------------------------------------------
// SHA-256 implementación pura (sin dependencias externas)
// ---------------------------------------------------------------------------
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static const DWORD k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(const BYTE* block, DWORD state[8])
{
    DWORD w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((DWORD)block[i*4] << 24) | ((DWORD)block[i*4+1] << 16) |
               ((DWORD)block[i*4+2] << 8) | (DWORD)block[i*4+3];
    }
    for (int i = 16; i < 64; i++) {
        DWORD s0 = ROTR(w[i-15], 7) ^ ROTR(w[i-15], 18) ^ (w[i-15] >> 3);
        DWORD s1 = ROTR(w[i-2], 17) ^ ROTR(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }

    DWORD a=state[0], b=state[1], c=state[2], d=state[3];
    DWORD e=state[4], f=state[5], g=state[6], h=state[7];

    for (int i = 0; i < 64; i++) {
        DWORD S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        DWORD ch = (e & f) ^ (~e & g);
        DWORD t1 = h + S1 + ch + k[i] + w[i];
        DWORD S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        DWORD maj = (a & b) ^ (a & c) ^ (b & c);
        DWORD t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void sha256(const BYTE* data, size_t len, BYTE out[32])
{
    DWORD state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    size_t i = 0;
    for (; i + 64 <= len; i += 64) {
        sha256_transform(data + i, state);
    }

    BYTE final_block[64];
    size_t rem = len - i;
    memcpy(final_block, data + i, rem);
    final_block[rem++] = 0x80;
    if (rem > 56) {
        memset(final_block + rem, 0, 64 - rem);
        sha256_transform(final_block, state);
        rem = 0;
    }
    memset(final_block + rem, 0, 56 - rem);
    DWORD bits = (DWORD)(len * 8);
    final_block[56] = (BYTE)(bits >> 24);
    final_block[57] = (BYTE)(bits >> 16);
    final_block[58] = (BYTE)(bits >> 8);
    final_block[59] = (BYTE)bits;
    final_block[60] = 0; final_block[61] = 0; final_block[62] = 0; final_block[63] = 0;
    sha256_transform(final_block, state);

    for (int j = 0; j < 8; j++) {
        out[j*4]     = (BYTE)(state[j] >> 24);
        out[j*4 + 1] = (BYTE)(state[j] >> 16);
        out[j*4 + 2] = (BYTE)(state[j] >> 8);
        out[j*4 + 3] = (BYTE)state[j];
    }
}

static BOOL hex_to_bytes(const char* hex, BYTE* out, size_t out_len)
{
    size_t len = strlen(hex);
    if (len != out_len * 2) return FALSE;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int v;
        if (sscanf_s(hex + i * 2, "%2x", &v) != 1) return FALSE;
        out[i] = (BYTE)v;
    }
    return TRUE;
}

// ---------------------------------------------------------------------------
// Lectura del parámetro de línea de comandos --sigkey-der
// ---------------------------------------------------------------------------
static BOOL ParseSigKeyPathFromCommandLine(char* outPath, size_t outPathSize)
{
    LPSTR cmdLine = GetCommandLineA();
    if (!cmdLine) return FALSE;

    // Copiamos a un buffer mutable para parsear
    static char cmdCopy[4096];
    size_t cmdLen = strlen(cmdLine);
    if (cmdLen >= sizeof(cmdCopy)) return FALSE;
    memcpy(cmdCopy, cmdLine, cmdLen + 1);

    char* context = nullptr;
    char* token = strtok_s(cmdCopy, " \t", &context);
    while (token != nullptr) {
        // Formato 1: --sigkey-der <ruta> (parámetro separado)
        if (_stricmp(token, "--sigkey-der") == 0 || _stricmp(token, "/sigkey-der") == 0) {
            token = strtok_s(nullptr, " \t", &context);
            if (token != nullptr) {
                strncpy_s(outPath, outPathSize, token, _TRUNCATE);
                return TRUE;
            }
        }
        // Formato 2: --sigkey-der=<ruta> o /sigkey-der:<ruta>
        else if (_strnicmp(token, "--sigkey-der=", 15) == 0) {
            strncpy_s(outPath, outPathSize, token + 15, _TRUNCATE);
            return TRUE;
        }
        else if (_strnicmp(token, "/sigkey-der:", 12) == 0) {
            strncpy_s(outPath, outPathSize, token + 12, _TRUNCATE);
            return TRUE;
        }
        token = strtok_s(nullptr, " \t", &context);
    }
    return FALSE;
}

// ---------------------------------------------------------------------------
// Utilidades PE en memoria
// ---------------------------------------------------------------------------
static BOOL GetSectionRange(HMODULE hModule, const char* sectionName, BYTE** outStart, SIZE_T* outSize)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, sectionName, 8) == 0) {
            *outStart = (BYTE*)hModule + sections[i].VirtualAddress;
            *outSize = sections[i].Misc.VirtualSize;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL GetImageSize(HMODULE hModule, SIZE_T* outSize)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
    if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    *outSize = nt->OptionalHeader.SizeOfImage;
    return TRUE;
}

// ---------------------------------------------------------------------------
// Búsqueda exacta de la clave por patrón SPKI + SHA-256
// ---------------------------------------------------------------------------
static BOOL ScanMemoryForKeyExact(BYTE* start, SIZE_T size, const BYTE* targetHash, BYTE** outAddr)
{
    if (!start || size < PATTERN_SIZE) return FALSE;

    for (SIZE_T i = 0; i + PATTERN_SIZE <= size; i++) {
        if (memcmp(start + i, SPKI_PATTERN, PATTERN_SIZE) == 0) {
            if (i + KEY_SIZE > size) continue;

            BYTE hash[32];
            sha256(start + i, KEY_SIZE, hash);

            if (memcmp(hash, targetHash, 32) == 0) {
                DebugLog("Clave identificada por SHA-256 en %p (offset +0x%zx)\n",
                         start + i, i);
                *outAddr = start + i;
                return TRUE;
            }
        }
    }
    return FALSE;
}

static BOOL FindKeyAddressExact(HMODULE hGame, BYTE** outAddr)
{
    BYTE targetHash[32];
    if (!hex_to_bytes(ORIGINAL_KEY_SHA256_HEX, targetHash, 32)) {
        DebugLog("Error: hash de referencia mal formado\n");
        return FALSE;
    }

    // 1) Escanear la sección .rdata (lugar habitual de la clave embebida)
    BYTE* sectionStart = nullptr;
    SIZE_T sectionSize = 0;
    if (GetSectionRange(hGame, ".rdata", &sectionStart, &sectionSize)) {
        DebugLog("Escaneando sección .rdata (%p, %zu bytes) por clave RSA-2048...\n",
                 sectionStart, sectionSize);
        BYTE* found = nullptr;
        if (ScanMemoryForKeyExact(sectionStart, sectionSize, targetHash, &found)) {
            *outAddr = found;
            return TRUE;
        }
        DebugLog("Clave no encontrada en .rdata\n");
    } else {
        DebugLog("No se pudo obtener el rango de la sección .rdata\n");
    }

    // 2) Escanear toda la imagen mapeada en memoria (fallback para otras compilaciones)
    SIZE_T imageSize = 0;
    if (GetImageSize(hGame, &imageSize)) {
        DebugLog("Escaneando imagen completa (%zu bytes) por clave RSA-2048...\n",
                 imageSize);
        BYTE* found = nullptr;
        if (ScanMemoryForKeyExact((BYTE*)hGame, imageSize, targetHash, &found)) {
            *outAddr = found;
            return TRUE;
        }
        DebugLog("Clave no encontrada en la imagen completa\n");
    }

    DebugLog("ERROR: no se pudo localizar automáticamente la clave pública embebida\n");
    return FALSE;
}

// ---------------------------------------------------------------------------
// Lectura de sigkey.der (solo desde la ruta pasada por parámetro)
// ---------------------------------------------------------------------------
static BOOL LoadKeyDerFromParam(const char* keyPath, BYTE* out, size_t outSize, size_t* outRead)
{
    *outRead = 0;

    if (!keyPath || keyPath[0] == '\0') {
        DebugLog("No se especificó ruta de sigkey.der (usa --sigkey-der <ruta>)\n");
        return FALSE;
    }

    FILE* f = nullptr;
    errno_t err = fopen_s(&f, keyPath, "rb");
    if (err != 0 || !f) {
        DebugLog("No se pudo abrir sigkey.der: %s\n", keyPath);
        return FALSE;
    }

    size_t read = fread(out, 1, outSize, f);
    fclose(f);

    if (read != outSize) {
        DebugLog("sigkey.der tiene %zu bytes, se esperaban %zu\n", read, outSize);
        return FALSE;
    }

    *outRead = read;
    DebugLog("Cargada clave pública desde %s (%zu bytes)\n", keyPath, read);
    return TRUE;
}

// ---------------------------------------------------------------------------
// Sustitución de la clave en memoria
// ---------------------------------------------------------------------------
static BOOL SubstituteKey(const char* keyPath)
{
    BYTE newKey[KEY_SIZE];
    size_t read = 0;
    if (!LoadKeyDerFromParam(keyPath, newKey, KEY_SIZE, &read)) {
        return FALSE;
    }

    HMODULE hGame = GetModuleHandleA(NULL);
    if (!hGame) {
        DebugLog("No se pudo obtener el base del módulo del juego\n");
        return FALSE;
    }

    DebugLog("Base del módulo del juego: %p\n", hGame);

    BYTE* keyAddr = nullptr;
    if (!FindKeyAddressExact(hGame, &keyAddr)) {
        return FALSE;
    }

    DWORD oldProtect = 0;
    if (!VirtualProtect(keyAddr, KEY_SIZE, PAGE_READWRITE, &oldProtect)) {
        DebugLog("VirtualProtect falló en %p, error %lu\n", keyAddr, GetLastError());
        return FALSE;
    }

    memcpy(keyAddr, newKey, KEY_SIZE);

    DWORD dummy = 0;
    VirtualProtect(keyAddr, KEY_SIZE, oldProtect, &dummy);

    DebugLog("Clave pública sustituida en %p (offset +0x%zx, %zu bytes)\n",
             keyAddr, keyAddr - (BYTE*)hGame, KEY_SIZE);
    return TRUE;
}

// ---------------------------------------------------------------------------
// DllMain
// ---------------------------------------------------------------------------
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        DebugLogOpen(hModule);
        DebugLog("=== FakeSignKey cargado ===\n");

        char keyPath[MAX_PATH] = {0};
        if (ParseSigKeyPathFromCommandLine(keyPath, MAX_PATH)) {
            DebugLog("Ruta de sigkey.der desde parámetro: %s\n", keyPath);
            if (SubstituteKey(keyPath)) {
                DebugLog("Clave pública sustituida correctamente.\n");
            } else {
                DebugLog("ADVERTENCIA: no se pudo sustituir la clave pública.\n");
            }
        } else {
            DebugLog("ERROR: no se especificó --sigkey-der <ruta> en la línea de comandos.\n");
            DebugLog("Ejemplo: AoE2DE_s.exe --sigkey-der C:\\ruta\\a\\sigkey.der\n");
        }
        break;
    }

    case DLL_PROCESS_DETACH: {
        DebugLog("=== FakeSignKey descargado ===\n");
        DebugLogClose();
        break;
    }
    }
    return TRUE;
}
