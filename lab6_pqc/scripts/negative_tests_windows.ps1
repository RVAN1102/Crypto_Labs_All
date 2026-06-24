[CmdletBinding()]
param([string]$BuildDir = "build-windows-mingw", [string]$OpenSSLRoot = "")
$Root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot "_common_windows.ps1")
[void](Initialize-PqOpenSSL $OpenSSLRoot)
$Exe = Resolve-Pqtool $Root $BuildDir
$Work = Join-Path $Root "artifacts\windows\demos\negative"
$Logs = Join-Path $Root "artifacts\windows\logs"
New-Item -ItemType Directory -Force -Path $Work, $Logs | Out-Null
Get-ChildItem $Work -ErrorAction SilentlyContinue | Remove-Item -Force
$failures = 0
function Expect-Failure([string]$Name, [string[]]$Arguments) {
    & $Exe @Arguments *> $null
    if ($LASTEXITCODE -eq 0) { "FAIL: $Name"; $script:failures++ } else { "PASS: $Name" }
}
function Tamper-FirstByte([string]$Input, [string]$Output) {
    $bytes = [System.IO.File]::ReadAllBytes($Input); $bytes[0] = $bytes[0] -bxor 1
    [System.IO.File]::WriteAllBytes($Output, $bytes)
}
& {
    [System.IO.File]::WriteAllText((Join-Path $Work "msg"), "negative", [System.Text.UTF8Encoding]::new($false))
    Invoke-Pq $Exe @("keygen","--algo","mldsa-44","--pub",(Join-Path $Work "dsa.pub"),"--priv",(Join-Path $Work "dsa.priv"))
    Invoke-Pq $Exe @("keygen","--algo","mldsa-44","--pub",(Join-Path $Work "wrong.pub"),"--priv",(Join-Path $Work "wrong.priv"))
    Invoke-Pq $Exe @("sign","--algo","mldsa-44","--priv",(Join-Path $Work "dsa.priv"),"--in",(Join-Path $Work "msg"),"--out",(Join-Path $Work "sig"))
    [System.IO.File]::WriteAllText((Join-Path $Work "modified-msg"), "modified", [System.Text.UTF8Encoding]::new($false))
    Tamper-FirstByte (Join-Path $Work "sig") (Join-Path $Work "modified-sig")
    Expect-Failure "modified ML-DSA message" @("verify","--algo","mldsa-44","--pub",(Join-Path $Work "dsa.pub"),"--in",(Join-Path $Work "modified-msg"),"--sig",(Join-Path $Work "sig"))
    Expect-Failure "modified ML-DSA signature" @("verify","--algo","mldsa-44","--pub",(Join-Path $Work "dsa.pub"),"--in",(Join-Path $Work "msg"),"--sig",(Join-Path $Work "modified-sig"))
    Expect-Failure "wrong ML-DSA public key" @("verify","--algo","mldsa-44","--pub",(Join-Path $Work "wrong.pub"),"--in",(Join-Path $Work "msg"),"--sig",(Join-Path $Work "sig"))
    Expect-Failure "unsupported algorithm" @("keygen","--algo","bad","--pub","x","--priv","y")
    Expect-Failure "missing file" @("sign","--algo","mldsa-44","--priv",(Join-Path $Work "dsa.priv"),"--in",(Join-Path $Work "missing"),"--out","x")
    [System.IO.File]::WriteAllText((Join-Path $Work "bad"), "bad")
    Expect-Failure "malformed private key" @("sign","--algo","mldsa-44","--priv",(Join-Path $Work "bad"),"--in",(Join-Path $Work "msg"),"--out","x")
    Expect-Failure "malformed public key" @("verify","--algo","mldsa-44","--pub",(Join-Path $Work "bad"),"--in",(Join-Path $Work "msg"),"--sig",(Join-Path $Work "sig"))
    Invoke-Pq $Exe @("keygen","--algo","mlkem-512","--pub",(Join-Path $Work "kem.pub"),"--priv",(Join-Path $Work "kem.priv"))
    Invoke-Pq $Exe @("keygen","--algo","mlkem-512","--pub",(Join-Path $Work "wrong-kem.pub"),"--priv",(Join-Path $Work "wrong-kem.priv"))
    Invoke-Pq $Exe @("encaps","--algo","mlkem-512","--pub",(Join-Path $Work "kem.pub"),"--ct",(Join-Path $Work "ct"),"--ss",(Join-Path $Work "expected"))
    Tamper-FirstByte (Join-Path $Work "ct") (Join-Path $Work "modified-ct")
    Invoke-Pq $Exe @("decaps","--algo","mlkem-512","--priv",(Join-Path $Work "kem.priv"),"--ct",(Join-Path $Work "modified-ct"),"--ss",(Join-Path $Work "modified-ss"))
    if (Test-BytesEqual (Join-Path $Work "expected") (Join-Path $Work "modified-ss")) { "FAIL: modified ML-KEM ciphertext"; $failures++ } else { "PASS: modified ML-KEM ciphertext" }
    Invoke-Pq $Exe @("decaps","--algo","mlkem-512","--priv",(Join-Path $Work "wrong-kem.priv"),"--ct",(Join-Path $Work "ct"),"--ss",(Join-Path $Work "wrong-ss"))
    if (Test-BytesEqual (Join-Path $Work "expected") (Join-Path $Work "wrong-ss")) { "FAIL: wrong ML-KEM private key"; $failures++ } else { "PASS: wrong ML-KEM private key" }
    Invoke-Pq $Exe @("cert-create","--subject","Student Lab 6","--subject-pub",(Join-Path $Work "dsa.pub"),"--issuer","PQ-CA","--ca-priv",(Join-Path $Work "dsa.priv"),"--out",(Join-Path $Work "cert"))
    $cert = [System.IO.File]::ReadAllText((Join-Path $Work "cert"))
    [System.IO.File]::WriteAllText((Join-Path $Work "subject-cert"), $cert.Replace("Student Lab 6","Mallory"))
    Expect-Failure "tampered certificate subject" @("cert-verify","--cert",(Join-Path $Work "subject-cert"),"--ca-pub",(Join-Path $Work "dsa.pub"))
    foreach ($field in "public_key_pem_b64","signature_b64") {
        $changed = [regex]::Replace($cert, "(`"$field`":`")([A-Za-z0-9+/])", { param($m) $m.Groups[1].Value + $(if ($m.Groups[2].Value -eq "A") {"B"} else {"A"}) }, 1)
        $path = Join-Path $Work "$field-cert"; [System.IO.File]::WriteAllText($path, $changed)
        Expect-Failure "tampered certificate $field" @("cert-verify","--cert",$path,"--ca-pub",(Join-Path $Work "dsa.pub"))
    }
    if ($failures -ne 0) { throw "$failures negative test(s) failed." }
    "NEGATIVE TESTS PASS"
} 2>&1 | Tee-Object (Join-Path $Logs "negative_tests_windows.log")
