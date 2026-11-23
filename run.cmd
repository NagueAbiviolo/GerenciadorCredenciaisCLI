@echo off
setlocal

:: Usa MSYS2_ROOT se definida (padrao: C:\msys64) e adiciona mingw64\bin ao PATH se existir
if defined MSYS2_ROOT (
    set "MSYS2_DIR=%MSYS2_ROOT%"
) else (
    set "MSYS2_DIR=C:\msys64"
)

set "PATH=%USERPROFILE%\.cargo\bin;%PATH%"
if exist "%MSYS2_DIR%\mingw64\bin\" (
    set "PATH=%MSYS2_DIR%\mingw64\bin;%PATH%"
)

:: Repassa todos os argumentos recebidos para o cargo run
cargo run -q --bin cofre -- %*

endlocal
