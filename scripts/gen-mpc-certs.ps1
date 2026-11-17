param(
    [string]$OutDir = 'certs/mpc-dev',
    [string[]]$Configs = @('configs/node-1.json', 'configs/node-2.json', 'configs/node-3.json')
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
Push-Location -LiteralPath $repo
try {
    go run ./cmd/mpc-certgen -out $OutDir @Configs
    if ($LASTEXITCODE -ne 0) { throw 'MPC certificate generation failed.' }
} finally {
    Pop-Location
}
