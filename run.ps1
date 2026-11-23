param (
    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$Args
)

# Usa MSYS2_ROOT se definida (padrão: C:\msys64) e adiciona mingw64\bin ao PATH se existir
$msys2Root = if ($env:MSYS2_ROOT) { $env:MSYS2_ROOT } else { "C:\msys64" }
$mingwBin = Join-Path $msys2Root "mingw64\bin"

$env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH"
if (Test-Path -Path $mingwBin -PathType Container) {
    $env:PATH = "$mingwBin;$env:PATH"
}

# Repassa os argumentos para o cargo run
cargo run -q --bin cofre -- $Args
