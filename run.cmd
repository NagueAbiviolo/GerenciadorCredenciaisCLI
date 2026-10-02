@echo off
setlocal

:: Adiciona o compilador do MSYS2 ao PATH temporariamente para esta execucao
set "PATH=C:\msys64\mingw64\bin;%USERPROFILE%\.cargo\bin;%PATH%"

:: Repassa todos os argumentos recebidos para o cargo run
cargo run -q --bin cofre -- %*

endlocal
