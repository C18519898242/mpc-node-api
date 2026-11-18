param(
    [string[]]$Configs = @('configs/node-1.json', 'configs/node-2.json', 'configs/node-3.json'),
    [switch]$Smoke
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$processes = @()
Push-Location -LiteralPath $repo
try {
    if ($Configs.Count -ne 3) { throw 'Provide exactly three node configs.' }
    $paths = @($Configs | ForEach-Object { (Resolve-Path -LiteralPath $_).Path })
    $nodes = @($paths | ForEach-Object { Get-Content -Raw -LiteralPath $_ | ConvertFrom-Json })
    if (@($nodes.partyId | Sort-Object -Unique).Count -ne 3) {
        throw 'Node configs must have distinct party IDs.'
    }

    $binary = Join-Path $repo 'mpc-node-api.exe'
    go build -o $binary .
    if ($LASTEXITCODE -ne 0) { throw 'Go build failed.' }

    foreach ($path in $paths) {
        $processes += Start-Process -FilePath $binary -ArgumentList @('-config', ('"{0}"' -f $path)) -PassThru -NoNewWindow
    }
    $urls = @($nodes | ForEach-Object { "http://$($_.restAddr)" })
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    foreach ($url in $urls) {
        while ($true) {
            if ($processes.HasExited -contains $true) { throw 'A node exited during startup.' }
            try {
                if ((Invoke-RestMethod "$url/healthz" -TimeoutSec 2).status -eq 'ok') { break }
            } catch {
                if ([DateTime]::UtcNow -ge $deadline) { throw }
            }
            if ([DateTime]::UtcNow -ge $deadline) { throw "Node failed health check at $url." }
            Start-Sleep -Milliseconds 200
        }
    }
    Write-Host "REST ready at $($urls -join ', ')"

    if ($Smoke) {
        $applications = [string[]]::new($nodes.Count)
        $headers = @(
            for ($i = 0; $i -lt $nodes.Count; $i++) {
                $node = $nodes[$i]
                $header = @{}
                if ($null -ne $node.restAuth) {
                    $envName = "MPC_NODE_API_KEY_$($node.partyId)"
                    $credential = [Environment]::GetEnvironmentVariable($envName)
                    if ([string]::IsNullOrWhiteSpace($credential)) {
                        throw "Set $envName for the authenticated smoke test."
                    }
                    $header.Authorization = "APIKEY $credential"
                    $hasher = [Security.Cryptography.SHA256]::Create()
                    try {
                        $digest = [Convert]::ToBase64String($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($credential)))
                    } finally {
                        $hasher.Dispose()
                    }
                    $matched = @($node.restAuth.apiKeys | Where-Object { $_.sha256 -ceq $digest })
                    if ($matched.Count -ne 1) { throw "$envName does not match the node config." }
                    $applications[$i] = $matched[0].applicationID
                }
                $header
            }
        )
        $sessionId = [Guid]::NewGuid().ToString('N')
        $body = @{ sessionId = $sessionId } | ConvertTo-Json -Compress
        for ($i = 0; $i -lt $urls.Count; $i++) {
            Invoke-RestMethod "$($urls[$i])/v1/keygen" -Method Post -Headers $headers[$i] -ContentType 'application/json' -Body $body -TimeoutSec 5 | Out-Null
        }
        $deadline = [DateTime]::UtcNow.AddMinutes(3.2)
        do {
            $results = @(for ($i = 0; $i -lt $urls.Count; $i++) {
                Invoke-RestMethod "$($urls[$i])/v1/sessions/$sessionId" -Headers $headers[$i] -TimeoutSec 5
            })
            if ($results.state -contains 'failed') { throw 'Keygen failed.' }
            if (@($results | Where-Object { $_.state -eq 'succeeded' }).Count -eq 3) { break }
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Keygen timed out.' }
            Start-Sleep -Milliseconds 300
        } while ($true)
        $publicKeys = @($results.publicKey | Sort-Object -Unique)
        if ($publicKeys.Count -ne 1 -or $publicKeys[0] -cnotmatch '^(02|03)[0-9a-f]{64}$') {
            throw "Nodes did not return the same compressed secp256k1 public key."
        }
        $shareFiles = @(
            for ($i = 0; $i -lt $paths.Count; $i++) {
                $dir = $nodes[$i].dataDir
                if (![IO.Path]::IsPathRooted($dir)) { $dir = Join-Path (Split-Path -Parent $paths[$i]) $dir }
                if ($applications[$i] -and $applications[$i] -cne 'default') {
                    $appDir = -join ([Text.Encoding]::UTF8.GetBytes($applications[$i]) | ForEach-Object { $_.ToString('x2') })
                    $dir = Join-Path (Join-Path $dir 'applications') $appDir
                }
                Get-Item -LiteralPath (Join-Path $dir "cmp-$sessionId.share")
            }
        )
        if (@($shareFiles.FullName | Sort-Object -Unique).Count -ne 3 -or ($shareFiles.Length -contains 0)) {
            throw 'Expected three independent, nonempty share files.'
        }
        Write-Host 'CMP 3-of-3 keygen passed. Public keys match and all three share files exist.'
    } else {
        Write-Host 'Press Ctrl+C to stop all nodes.'
        while ($processes.HasExited -notcontains $true) { Start-Sleep -Milliseconds 500 }
        throw 'A node exited.'
    }
} finally {
    foreach ($process in $processes) {
        if (!$process.HasExited) {
            Stop-Process -InputObject $process -ErrorAction SilentlyContinue
            $process.WaitForExit()
        }
    }
    Pop-Location
}
