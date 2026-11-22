param([switch]$Smoke)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$processes = @()
Push-Location -LiteralPath $repo
try {
    $serverPasswordFile = Join-Path $repo 'certs/mpc-master-passwords.ps1'
    if (!(Test-Path -LiteralPath $serverPasswordFile)) {
        throw 'Expected existing certs/mpc-master-passwords.ps1. Configure the server passwords before running this demo.'
    }
    foreach ($file in @('ca.crt', 'node-1/node.crt', 'node-1/node.key', 'node-2/node.crt', 'node-2/node.key', 'node-3/node.crt', 'node-3/node.key')) {
        if (!(Test-Path -LiteralPath (Join-Path $repo "certs/mpc-dev/$file"))) {
            throw 'Expected existing certs/mpc-dev certificates. This script never replaces certificates.'
        }
    }
    foreach ($port in @(8182, 8183, 9182, 9183)) {
        $probe = [Net.Sockets.TcpClient]::new()
        try {
            $occupied = $false
            try { $probe.Connect('127.0.0.1', $port); $occupied = $true } catch { }
            if ($occupied) { throw 'A mobile demo port (8182/8183/9182/9183) is already in use. Stop that process before starting the demo.' }
        } finally { $probe.Dispose() }
    }
    . $serverPasswordFile
    if ([string]::IsNullOrWhiteSpace($env:MPC_NODE_2_MASTER_PASSWORD) -or [string]::IsNullOrWhiteSpace($env:MPC_NODE_3_MASTER_PASSWORD)) {
        throw 'Expected MPC_NODE_2_MASTER_PASSWORD and MPC_NODE_3_MASTER_PASSWORD in the server password file.'
    }
    $mobilePasswordFile = Join-Path $repo 'certs/mobile-dev-passwords.ps1'
    if (!(Test-Path -LiteralPath $mobilePasswordFile)) {
        $bytes = [byte[]]::new(32)
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
        $password = [Convert]::ToBase64String($bytes)
        $line = '$env:MPC_MOBILE_MASTER_PASSWORD = ''' + $password + "'`r`n"
        # CreateNew prevents a concurrent launch from overwriting an existing password.
        $stream = [IO.File]::Open($mobilePasswordFile, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
        try {
            $encoded = [Text.Encoding]::ASCII.GetBytes($line)
            $stream.Write($encoded, 0, $encoded.Length)
        } finally { $stream.Dispose() }
        [Array]::Clear($bytes, 0, $bytes.Length)
        $password = $null
        $line = $null
    }
    . $mobilePasswordFile
    if ([string]::IsNullOrWhiteSpace($env:MPC_MOBILE_MASTER_PASSWORD)) {
        throw 'Expected MPC_MOBILE_MASTER_PASSWORD in certs/mobile-dev-passwords.ps1.'
    }
    $devKeys = Get-Content -Raw -LiteralPath (Join-Path $repo 'configs/dev-api-keys.json') | ConvertFrom-Json
    $env:MPC_NODE_API_KEY_2 = $devKeys.'2'.'wallet-a'
    $env:MPC_NODE_API_KEY_3 = $devKeys.'3'.'wallet-a'

    $binDir = Join-Path $repo 'data/mobile-demo/bin'
    $logDir = Join-Path $repo 'data/mobile-demo/logs'
    New-Item -ItemType Directory -Path $binDir, $logDir -Force | Out-Null
    $serverBinary = Join-Path $binDir 'mpc-node-api.exe'
    $mobileBinary = Join-Path $binDir 'mobile-sim.exe'
    go build -o $serverBinary .
    if ($LASTEXITCODE -ne 0) { throw 'Server build failed.' }
    go build -o $mobileBinary ./cmd/mobile-sim
    if ($LASTEXITCODE -ne 0) { throw 'Mobile simulator build failed.' }

    foreach ($id in @(2, 3)) {
        $configPath = Join-Path $repo "configs/mobile/server-$id.json"
        $processes += Start-Process -FilePath $serverBinary -ArgumentList @('-config', ('"{0}"' -f $configPath)) -WorkingDirectory $repo -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $logDir "node-$id.stdout.log") -RedirectStandardError (Join-Path $logDir "node-$id.stderr.log")
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    foreach ($port in @(8182, 8183)) {
        while ($true) {
            if ($processes.HasExited -contains $true) { throw 'A server exited during startup; inspect data/mobile-demo/logs.' }
            try {
                if ((Invoke-RestMethod "http://127.0.0.1:$port/healthz" -TimeoutSec 2).status -eq 'ok') { break }
            } catch { }
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Server health check timed out; inspect data/mobile-demo/logs.' }
            Start-Sleep -Milliseconds 200
        }
    }
    Write-Host 'Two mobile-demo servers are ready; the phone opens no listening port.'
    foreach ($db in @('data/mobile-sim/node.sqlite', 'data/mobile-demo/node-2/node.sqlite', 'data/mobile-demo/node-3/node.sqlite')) {
        Write-Host ([IO.Path]::GetFullPath((Join-Path $repo $db)))
    }
    if ($Smoke) {
        foreach ($algorithm in @('ecdsa', 'frost')) {
            $keyID = "mobile-$algorithm-$([Guid]::NewGuid().ToString('N').Substring(0, 12))"
            $createdJSON = @(& $mobileBinary keygen -config configs/mobile/mobile.json -algorithm $algorithm -threshold 2 -key-id $keyID)
            if ($LASTEXITCODE -ne 0) { throw "$algorithm keygen failed." }
            $created = ($createdJSON -join "`n") | ConvertFrom-Json
            # A separate process must unlock and read the existing phone database.
            $signedJSON = @(& $mobileBinary sign -config configs/mobile/mobile.json -algorithm $algorithm -key-id $keyID -message 'mobile simulator restart smoke')
            if ($LASTEXITCODE -ne 0) { throw "$algorithm signing after reopen failed." }
            $signed = ($signedJSON -join "`n") | ConvertFrom-Json
            if ($created.keyID -cne $keyID -or $signed.keyID -cne $keyID -or !$created.publicKey -or $created.publicKey -cne $signed.publicKey -or $created.curve -cne $signed.curve -or !$signed.signature) {
                throw "$algorithm returned mismatched public results."
            }
            if ([Convert]::FromBase64String($signed.signature).Length -eq 0) { throw "$algorithm returned an empty signature." }
            Write-Host "$algorithm create/reopen/sign passed; public keys match and the mobile client verified the signature."

            $batchJSON = @(& $mobileBinary presiggen -config configs/mobile/mobile.json -algorithm $algorithm -key-id $keyID -count 2)
            if ($LASTEXITCODE -ne 0) { throw "$algorithm presiggen failed." }
            $batch = ($batchJSON -join "`n") | ConvertFrom-Json
            if (@($batch.ids).Count -ne 2 -or !$batch.ids[0] -or $batch.ids[0] -ceq $batch.ids[1]) { throw "$algorithm returned invalid presignature IDs." }
            $presignedJSON = @(& $mobileBinary signwithpresig -config configs/mobile/mobile.json -algorithm $algorithm -key-id $keyID -presignature-id $batch.ids[0] -message 'mobile presign restart smoke')
            if ($LASTEXITCODE -ne 0) { throw "$algorithm presign signing after reopen failed." }
            $presigned = ($presignedJSON -join "`n") | ConvertFrom-Json
            if ($presigned.keyID -cne $keyID -or $presigned.presignatureId -cne $batch.ids[0] -or $presigned.publicKey -cne $created.publicKey -or $presigned.curve -cne $created.curve -or !$presigned.signature) {
                throw "$algorithm returned invalid combined presignature results."
            }
            $reused = Start-Process -FilePath $mobileBinary -ArgumentList @('signwithpresig', '-config', 'configs/mobile/mobile.json', '-algorithm', $algorithm, '-key-id', $keyID, '-presignature-id', $batch.ids[0], '-message', 'reused') -WorkingDirectory $repo -WindowStyle Hidden -Wait -PassThru -RedirectStandardOutput (Join-Path $logDir "$algorithm-reused.stdout.log") -RedirectStandardError (Join-Path $logDir "$algorithm-reused.stderr.log")
            if ($reused.ExitCode -eq 0) { throw "$algorithm accepted an already consumed presignature." }
            foreach ($id in @(2, 3)) {
                $headers = @{ Authorization = 'APIKEY ' + $devKeys."$id".'wallet-a' }
                $remaining = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:818$id/key/$keyID/count/presigs" -Headers $headers -ContentType 'application/json' -Body '{}'
                if ($remaining -ne 1) { throw "$algorithm server $id has an unexpected presignature count." }
            }
            Write-Host "$algorithm presiggen/reopen/signwithpresig/reuse-rejected passed; keyID=$keyID; remaining presignatureId=$($batch.ids[1])."
        }
        foreach ($db in @('data/mobile-sim/node.sqlite', 'data/mobile-demo/node-2/node.sqlite', 'data/mobile-demo/node-3/node.sqlite')) {
            if (!(Test-Path -LiteralPath $db) -or (Get-Item -LiteralPath $db).Length -eq 0) { throw 'Expected nonempty phone and server SQLite databases.' }
        }
    } else {
        Write-Host 'Run the mobile CLI from another terminal (see docs/mobile-nodes.md). Press Ctrl+C to stop these two servers.'
        while ($processes.HasExited -notcontains $true) { Start-Sleep -Milliseconds 500 }
        throw 'A mobile-demo server exited; inspect data/mobile-demo/logs.'
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
