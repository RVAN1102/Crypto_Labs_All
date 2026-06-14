param(
    [string]$Dir = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $PSCommandPath
$Lab4Root = Split-Path -Parent $ScriptDir
if ([string]::IsNullOrWhiteSpace($Dir)) {
    $Dir = Join-Path $Lab4Root "demos\md5_collision"
}

$FileA = Join-Path $Dir "collision_a.bin"
$FileB = Join-Path $Dir "collision_b.bin"

if (!(Test-Path -LiteralPath $FileA) -or !(Test-Path -LiteralPath $FileB)) {
    throw "missing collision files: $FileA and/or $FileB"
}

$Md5A = (Get-FileHash -Algorithm MD5 -LiteralPath $FileA).Hash.ToLowerInvariant()
$Md5B = (Get-FileHash -Algorithm MD5 -LiteralPath $FileB).Hash.ToLowerInvariant()
$Sha256A = (Get-FileHash -Algorithm SHA256 -LiteralPath $FileA).Hash.ToLowerInvariant()
$Sha256B = (Get-FileHash -Algorithm SHA256 -LiteralPath $FileB).Hash.ToLowerInvariant()

if ($Md5A -ne $Md5B) {
    Write-Error "MD5 collision verification: FAIL`ncollision_a.bin MD5: $Md5A`ncollision_b.bin MD5: $Md5B"
    exit 1
}

if ($Sha256A -eq $Sha256B) {
    Write-Error "SHA-256 difference verification: FAIL`nboth files have SHA-256: $Sha256A"
    exit 1
}

Write-Host "MD5 collision verification: PASS"
Write-Host "SHA-256 difference verification: PASS"
Write-Host "collision_a_md5=$Md5A"
Write-Host "collision_b_md5=$Md5B"
Write-Host "collision_a_sha256=$Sha256A"
Write-Host "collision_b_sha256=$Sha256B"

