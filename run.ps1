param (
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Args
)

# Adiciona o compilador do MSYS2 ao PATH temporariamente para esta execução
$env:PATH = "C:\msys64\mingw64\bin;$env:USERPROFILE\.cargo\bin;$env:PATH"

# Repassa os argumentos para o cargo run
cargo run -q --bin cofre -- $Args
