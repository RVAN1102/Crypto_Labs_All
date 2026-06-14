param(
    [string]$Exe = ".\build\rsatool.exe",
    [string]$Log = ".\artifacts\windows\logs\manual_key_auto_windows.log"
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$Stamp = Get-Date -Format "yyyyMMdd_HHmmss_ffff"
$Work = Join-Path $Root "tmp_manual_verify\$Stamp"
New-Item -ItemType Directory -Force -Path $Work | Out-Null

"Manual verification started" | Set-Content -Path $Log -Encoding ASCII
"Manual work dir: $Work" | Tee-Object -FilePath $Log -Append

function Invoke-Step($Name, [scriptblock]$Body) {
    "[STEP] $Name" | Tee-Object -FilePath $Log -Append
    & $Body
    "[PASS] $Name" | Tee-Object -FilePath $Log -Append
}

function Assert-Contains($Text, $Needle, $Name) {
    if (!$Text.Contains($Needle)) {
        throw "$Name missing: $Needle"
    }
}

function Assert-BytesEqual($A, $B, $Name) {
    $AB = [IO.File]::ReadAllBytes($A)
    $BB = [IO.File]::ReadAllBytes($B)

    if ($AB.Length -ne $BB.Length) {
        throw "$Name length mismatch"
    }

    for ($i = 0; $i -lt $AB.Length; $i++) {
        if ($AB[$i] -ne $BB[$i]) {
            throw "$Name byte mismatch at $i"
        }
    }
}

if (!(Test-Path $Exe)) {
    throw "Executable not found: $Exe"
}

$PrivDer = Join-Path $Work "private.der"
$PubDer = Join-Path $Work "public.der"
$DerMeta = Join-Path $Work "der_metadata.json"

Invoke-Step "DER keygen with metadata" {
    & $Exe keygen --bits 3072 --private $PrivDer --public $PubDer --meta $DerMeta 2>&1 |
        Tee-Object -FilePath $Log -Append

    if ($LASTEXITCODE -ne 0) {
        throw "DER keygen failed"
    }

    $Meta = Get-Content $DerMeta -Raw
    Assert-Contains $Meta '"modulus_bits": 3072' "DER metadata"
    Assert-Contains $Meta '"hash": "SHA-256"' "DER metadata"
    Assert-Contains $Meta '"padding": "OAEP"' "DER metadata"
    Assert-Contains $Meta '"mgf": "MGF1-SHA256"' "DER metadata"
}

$PrivPem = Join-Path $Work "private.pem"
$PubPem = Join-Path $Work "public.pem"
$PemMeta = Join-Path $Work "pem_metadata.json"

Invoke-Step "PEM keygen with metadata" {
    & $Exe keygen --bits 3072 --priv $PrivPem --pub $PubPem --meta $PemMeta 2>&1 |
        Tee-Object -FilePath $Log -Append

    if ($LASTEXITCODE -ne 0) {
        throw "PEM keygen failed"
    }

    Assert-Contains (Get-Content $PrivPem -Raw) "BEGIN RSA PRIVATE KEY" "private PEM"
    Assert-Contains (Get-Content $PubPem -Raw) "BEGIN RSA PUBLIC KEY" "public PEM"

    $Meta = Get-Content $PemMeta -Raw
    Assert-Contains $Meta '"private_key_file"' "PEM metadata"
    Assert-Contains $Meta '"public_key_file"' "PEM metadata"
}

Invoke-Step "small auto RSA encrypt/decrypt" {
    $Small = Join-Path $Work "small.txt"
    $SmallCt = Join-Path $Work "small.ct"
    $SmallOut = Join-Path $Work "small.out"

    [IO.File]::WriteAllText($Small, "small plaintext for direct RSA", [Text.Encoding]::UTF8)

    & $Exe encrypt --pub $PubDer --in $Small --out $SmallCt --label-text verify 2>&1 |
        Tee-Object -FilePath $Log -Append

    if ($LASTEXITCODE -ne 0) {
        throw "small auto encrypt failed"
    }

    if (([IO.File]::ReadAllBytes($SmallCt)).Length -ne 384) {
        throw "small auto ciphertext is not RSA-3072 length"
    }

    if (Test-Path "$SmallCt.envelope.json") {
        throw "small auto unexpectedly created an envelope"
    }

    & $Exe decrypt --priv $PrivDer --in $SmallCt --out $SmallOut --label-text verify 2>&1 |
        Tee-Object -FilePath $Log -Append

    if ($LASTEXITCODE -ne 0) {
        throw "small auto decrypt failed"
    }

    Assert-BytesEqual $Small $SmallOut "small auto plaintext"
}

Invoke-Step "large auto hybrid encrypt/decrypt" {
    $Large = Join-Path $Work "large.bin"
    $LargeCt = Join-Path $Work "large.ct"
    $LargeOut = Join-Path $Work "large.out"

    [IO.File]::WriteAllBytes($Large, [byte[]](0..255 + 0..62))

    & $Exe encrypt --pub $PubPem --in $Large --out $LargeCt --label-text verify 2>&1 |
        Tee-Object -FilePath $Log -Append

    if ($LASTEXITCODE -ne 0) {
        throw "large auto encrypt failed"
    }

    $Envelope = "$LargeCt.envelope.json"
    if (!(Test-Path $Envelope)) {
        throw "large auto did not create default envelope"
    }

    $EnvelopeText = Get-Content $Envelope -Raw
    Assert-Contains $EnvelopeText "AES-256-GCM" "large envelope"
    Assert-Contains $EnvelopeText "RSA-OAEP-SHA256" "large envelope"

    & $Exe decrypt --priv $PrivPem --in $LargeCt --out $LargeOut --label-text verify 2>&1 |
        Tee-Object -FilePath $Log -Append

    if ($LASTEXITCODE -ne 0) {
        throw "large auto decrypt failed"
    }

    Assert-BytesEqual $Large $LargeOut "large auto plaintext"
}

"Manual verification passed" | Tee-Object -FilePath $Log -Append
