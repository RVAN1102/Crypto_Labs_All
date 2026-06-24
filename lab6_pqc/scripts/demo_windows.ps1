[CmdletBinding()]
param([string]$BuildDir = "build-windows-mingw", [string]$OpenSSLRoot = "")
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "_common_windows.ps1")
[void](Initialize-PqOpenSSL $OpenSSLRoot)
$Exe = Resolve-Pqtool $Root $BuildDir
$Demo = Join-Path $Root "artifacts\windows\demos"
$Keys = Join-Path $Root "artifacts\windows\keys"
$Certs = Join-Path $Root "artifacts\windows\certs"
$Logs = Join-Path $Root "artifacts\windows\logs"
foreach ($dir in $Demo, $Keys, $Certs, $Logs) { New-Item -ItemType Directory -Force $dir | Out-Null }
$Log = Join-Path $Logs "demo_windows.log"
& {
    [System.IO.File]::WriteAllBytes((Join-Path $Demo "message.bin"), [byte[]](76,97,98,32,54,0,255))
    Invoke-Pq $Exe @("keygen","--algo","mldsa-44","--pub",(Join-Path $Keys "ca.pub"),"--priv",(Join-Path $Keys "ca.priv"))
    Invoke-Pq $Exe @("keygen","--algo","mldsa-44","--pub",(Join-Path $Keys "subject.pub"),"--priv",(Join-Path $Keys "subject.priv"))
    Invoke-Pq $Exe @("sign","--algo","mldsa-44","--priv",(Join-Path $Keys "subject.priv"),"--in",(Join-Path $Demo "message.bin"),"--out",(Join-Path $Demo "message.sig"))
    Invoke-Pq $Exe @("verify","--algo","mldsa-44","--pub",(Join-Path $Keys "subject.pub"),"--in",(Join-Path $Demo "message.bin"),"--sig",(Join-Path $Demo "message.sig"))
    $tampered = [byte[]]([System.IO.File]::ReadAllBytes((Join-Path $Demo "message.bin")) + [byte]88)
    [System.IO.File]::WriteAllBytes((Join-Path $Demo "tampered.bin"), $tampered)
    & $Exe verify --algo mldsa-44 --pub (Join-Path $Keys "subject.pub") --in (Join-Path $Demo "tampered.bin") --sig (Join-Path $Demo "message.sig")
    if ($LASTEXITCODE -eq 0) { throw "Tampered message verified." }
    Invoke-Pq $Exe @("keygen","--algo","mlkem-512","--pub",(Join-Path $Keys "kem.pub"),"--priv",(Join-Path $Keys "kem.priv"))
    Invoke-Pq $Exe @("encaps","--algo","mlkem-512","--pub",(Join-Path $Keys "kem.pub"),"--ct",(Join-Path $Demo "kem.ct"),"--ss",(Join-Path $Demo "sender.ss"))
    Invoke-Pq $Exe @("decaps","--algo","mlkem-512","--priv",(Join-Path $Keys "kem.priv"),"--ct",(Join-Path $Demo "kem.ct"),"--ss",(Join-Path $Demo "recipient.ss"))
    if (-not (Test-BytesEqual (Join-Path $Demo "sender.ss") (Join-Path $Demo "recipient.ss"))) { throw "Shared secrets differ." }
    Invoke-Pq $Exe @("cert-create","--subject","Student Lab 6","--subject-pub",(Join-Path $Keys "subject.pub"),"--issuer","PQ-CA","--ca-priv",(Join-Path $Keys "ca.priv"),"--out",(Join-Path $Certs "cert.json"))
    Invoke-Pq $Exe @("cert-verify","--cert",(Join-Path $Certs "cert.json"),"--ca-pub",(Join-Path $Keys "ca.pub"))
    $text = [System.IO.File]::ReadAllText((Join-Path $Certs "cert.json")).Replace("Student Lab 6","Mallory")
    [System.IO.File]::WriteAllText((Join-Path $Certs "tampered.json"), $text, [System.Text.UTF8Encoding]::new($false))
    & $Exe cert-verify --cert (Join-Path $Certs "tampered.json") --ca-pub (Join-Path $Keys "ca.pub")
    if ($LASTEXITCODE -eq 0) { throw "Tampered certificate verified." }
    Invoke-Pq $Exe @("selftest")
    "DEMO PASS"
} 2>&1 | Tee-Object $Log
