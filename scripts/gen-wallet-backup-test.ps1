$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$testDir = Join-Path $repo 'certs/wallet-backup-test'
$templateDir = Join-Path $repo 'configs'
$configDir = Join-Path $testDir 'configs'

Push-Location -LiteralPath $repo
try {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    [IO.File]::WriteAllText((Join-Path $testDir 'TEST-ONLY.txt'), "Local test RSA keys. DO NOT use or deploy in production. Keep the private keys offline from the node processes.`n")
    $fingerprints = @{}
    foreach ($id in 1..3) {
        $nodeDir = Join-Path $testDir "node-$id"
        $files = @('rsa-private.pem', 'rsa-public.pem', 'rsa-public.der')
        $existing = @($files | Where-Object { Test-Path -LiteralPath (Join-Path $nodeDir $_) -PathType Leaf })
        if ($existing.Count -eq 0) {
            go run ./cmd/mpc-wrapkeygen -out $nodeDir
            if ($LASTEXITCODE -ne 0) { throw "Test RSA generation failed for node $id." }
        } elseif ($existing.Count -ne $files.Count) {
            throw "Node $id has an incomplete RSA key set at $nodeDir. Restore the missing files before continuing."
        }
        $publicFile = Join-Path $nodeDir 'rsa-public.der'
        $fingerprint = (Get-FileHash -LiteralPath $publicFile -Algorithm SHA256).Hash
        if ($fingerprints.ContainsKey($fingerprint)) { throw 'Test nodes must use different RSA public keys.' }
        $fingerprints[$fingerprint] = $true

        $cfg = Get-Content -Raw -LiteralPath (Join-Path $templateDir "node-$id.json") | ConvertFrom-Json -AsHashtable
        foreach ($field in @('caFile', 'certFile', 'keyFile')) {
            $cfg.mpcTLS[$field] = [IO.Path]::GetFullPath($cfg.mpcTLS[$field], $templateDir)
        }
        $cfg.dataDir = Join-Path $repo "data/wallet-backup-test/node-$id"
        $cfg.Remove('keyTransfer')
        $cfg.Remove('emergencyRecovery')
        $cfg.walletBackup = @{ publicKey = [Convert]::ToBase64String([IO.File]::ReadAllBytes($publicFile)) }
        [IO.File]::WriteAllText((Join-Path $configDir "node-$id.json"), ($cfg | ConvertTo-Json -Depth 12))
    }
    Write-Host "TEST ONLY — node configs and RSA test keys are in $testDir. Do not use these keys in production."
} finally {
    Pop-Location
}
