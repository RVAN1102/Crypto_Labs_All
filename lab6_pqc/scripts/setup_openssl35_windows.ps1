[CmdletBinding()]
param(
    [string]$OpenSSLRoot = "C:\OpenSSL-4.0"
)

$ErrorActionPreference = "Stop"

function Get-OpenSSLVersion {
    param([string]$Executable)

    $line = (& $Executable version 2>&1 | Select-Object -First 1)
    if ($LASTEXITCODE -ne 0 -or $line -notmatch '^OpenSSL\s+(\d+)\.(\d+)\.(\d+)') {
        throw "Could not determine the OpenSSL version from $Executable."
    }

    return [version]("{0}.{1}.{2}" -f $Matches[1], $Matches[2], $Matches[3])
}

$OpenSSLExe = Join-Path $OpenSSLRoot "bin\openssl.exe"
if (Test-Path -LiteralPath $OpenSSLExe) {
    $Version = Get-OpenSSLVersion -Executable $OpenSSLExe
    if ($Version -lt [version]"3.5.0") {
        throw "OpenSSL $Version is too old; Lab 6 requires OpenSSL 3.5.0 or newer."
    }

    $SignatureAlgorithms = (& $OpenSSLExe list -signature-algorithms 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $SignatureAlgorithms -notmatch 'ML-DSA') {
        throw "OpenSSL $Version does not advertise ML-DSA."
    }

    $KemAlgorithms = (& $OpenSSLExe list -kem-algorithms 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0 -or $KemAlgorithms -notmatch 'ML-KEM') {
        throw "OpenSSL $Version does not advertise ML-KEM."
    }

    Write-Host "PASS: OpenSSL $Version with ML-DSA and ML-KEM is available."
    Write-Host "Use CMake with: -DOPENSSL_ROOT_DIR=`"$OpenSSLRoot`""
    exit 0
}

Write-Host "No OpenSSL installation was found at $OpenSSLRoot."
Write-Host ""
Write-Host "Non-destructive source-build outline (x64 MSVC):"
Write-Host "  1. Install Visual Studio 2022 C++ tools, Perl, and NASM."
Write-Host "  2. Download and verify an OpenSSL 3.5.x source archive from:"
Write-Host "       https://www.openssl.org/source/"
Write-Host "  3. Open an x64 Native Tools Command Prompt for VS 2022."
Write-Host "  4. From the extracted source directory run:"
Write-Host "       perl Configure VC-WIN64A --prefix=`"$OpenSSLRoot`" --openssldir=`"$OpenSSLRoot\ssl`""
Write-Host "       nmake"
Write-Host "       nmake test"
Write-Host "       nmake install_sw"
Write-Host "  5. Rerun this script to validate ML-DSA and ML-KEM."
Write-Host ""
Write-Host "This custom prefix does not replace Windows system components."
exit 2
