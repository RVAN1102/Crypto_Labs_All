$ErrorActionPreference = "Stop"

function Initialize-PqOpenSSL {
    param([string]$OpenSSLRoot)
    if (-not $OpenSSLRoot) {
        if (Test-Path "C:\OpenSSL-4.0") { $OpenSSLRoot = "C:\OpenSSL-4.0" }
        elseif (Test-Path "C:\OpenSSL-3.5") { $OpenSSLRoot = "C:\OpenSSL-3.5" }
        else { throw "Specify -OpenSSLRoot; no C:\OpenSSL-4.0 or C:\OpenSSL-3.5 installation exists." }
    }
    $exe = Join-Path $OpenSSLRoot "bin\openssl.exe"
    if (-not (Test-Path $exe)) { throw "OpenSSL executable not found: $exe" }
    $env:PATH = "$(Join-Path $OpenSSLRoot 'bin');$env:PATH"
    $versionText = (& $exe version 2>&1 | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or $versionText -notmatch '^OpenSSL\s+(\d+\.\d+\.\d+)') {
        throw "Unable to run $exe. Check required OpenSSL DLLs."
    }
    if ([version]$Matches[1] -lt [version]"3.5.0") { throw "OpenSSL 3.5+ is required." }
    $sig = (& $exe list -signature-algorithms 2>&1) -join "`n"
    $kem = (& $exe list -kem-algorithms 2>&1) -join "`n"
    if ($sig -notmatch "ML-DSA" -or $kem -notmatch "ML-KEM") {
        throw "The OpenSSL provider does not advertise both ML-DSA and ML-KEM."
    }
    return $OpenSSLRoot
}

function Resolve-Pqtool {
    param([string]$Root, [string]$BuildDir)
    $mingw = Join-Path $Root "$BuildDir\pqtool.exe"
    $msvc = Join-Path $Root "$BuildDir\Release\pqtool.exe"
    if (Test-Path $mingw) { return $mingw }
    if (Test-Path $msvc) { return $msvc }
    throw "pqtool.exe was not found in $BuildDir."
}

function Invoke-Pq {
    param([string]$Exe, [string[]]$Arguments)
    & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "pqtool failed with exit code $LASTEXITCODE." }
}

function Test-BytesEqual {
    param([string]$Left, [string]$Right)
    $a = [System.IO.File]::ReadAllBytes($Left)
    $b = [System.IO.File]::ReadAllBytes($Right)
    if ($a.Length -ne $b.Length) { return $false }
    for ($i = 0; $i -lt $a.Length; $i++) {
        if ($a[$i] -ne $b[$i]) { return $false }
    }
    return $true
}

