# FakeSignKey — DLL multi-juego para ageLANServerLauncherCompanion

Este DLL sustituye la clave pública RSA-2048 embebida en los clientes de Age of
Empires (AoE2DE, AoE3DE, AoMRT y AoE4) por la clave pública del servidor
comunitario (`sigkey.der`), sin desactivar la comprobación de firma.

## Estructura

```
FakeSignKey/
├── dllmain.cpp         # Punto de entrada y lógica de sustitución
├── debuglog.cpp/h      # Logging consistente con otros DLL del launcher
├── pch.cpp/h           # Precompiled headers
├── framework.h         # Framework includes
├── resource.h          -> Resource IDs
├── resource.rc         -> Resource script
├── FakeSignKey.vcxproj  -> Proyecto Visual Studio (vcpkg, v145, stdcpp20)
├── build.bat           # Compilación con cl.exe
└── README.md           # este archivo
```

## Características

- **Multi-juego:** detecta automáticamente la clave en memoria por patrón SPKI +
  SHA-256, funciona en AoE2DE, AoE3DE, AoMRT y AoE4 sin necesidad de RVA
  hardcodeado.
- **Sin modificar .text:** solo sobrescribe los 294 bytes de la clave en `.rdata`,
  evitando la salida 4353 del cliente.
- **Consistencia:** sigue el mismo patrón que `Age2FakeOnline`, `Age3FakeOnline`
  y `AgeFakeHostsCerts` (debuglog, pch, vcxproj con vcpkg).
- **Nombre del DLL de salida:** `AgeFakeSignKey.dll` (coherente con la
  nomenclatura `Age*Fake*.dll` de los demás componentes).
- **Ruta de clave solo por parámetro:** el DLL no busca `sigkey.der` junto a sí
  mismo ni usa variables de entorno. La ruta se pasa en la línea de comandos del
  juego: `--sigkey-der <ruta>`.

## Despliegue

El proyecto ya está integrado en la solución `ageLANServerLauncherCompanion.sln`
como `FakeSignKey`. Compilar en Release x64 genera `AgeFakeSignKey.dll` en
`x64/Release/`.

El DLL se inyecta mediante el loader (`dlls` folder de ColdClientLoader).

## Claves soportadas

| Juego | Ejecutable | RVA de la clave | SHA-256 |
|-------|------------|-----------------|---------|
| AoE2DE | AoE2DE_s.exe | 0x3678F80 | 1cb03454... |
| AoE3DE | AoE3DE_s.exe | 0x2993CD0 | 1cb03454... |
| AoMRT | AoMRT_s.exe | 0x45D1310 | 1cb03454... |
| AoE4 | RelicCardinal.exe | 0x6170050 | 1cb03454... |

## Ejemplo de uso

```
AoE2DE_s.exe --sigkey-der F:\ageLANServer\build\server\resources\certificates\sigkey.der
```
