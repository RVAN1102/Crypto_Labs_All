param(
    [Parameter(Mandatory = $true)][string]$Exe,
    [Parameter(Mandatory = $true)][string]$Args,
    [Parameter(Mandatory = $true)][string]$Needle
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $Exe)) {
    throw "Executable not found: $Exe"
}

$ArgArray = $Args -split ' '
$Output = & $Exe @ArgArray 2>&1 | ForEach-Object { $_.ToString() }
$Code = $LASTEXITCODE
$Text = $Output -join "`n"

Write-Host $Text

if ($Code -ne 0) {
    throw "Command failed with exit code $Code"
}

if ($Text -notlike "*$Needle*") {
    throw "Expected output to contain: $Needle"
}

