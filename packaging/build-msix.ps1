<#
.SYNOPSIS
  Builds an MSIX package of the uEncrypt GUI (Windows only; needs Go, Node.js, the Wails CLI
  and the Windows 10/11 SDK for makeappx.exe).

.EXAMPLE
  # Store submission (unsigned; the Store signs it). Use the identity from Partner Center.
  ./packaging/build-msix.ps1 -Version 1.0.0.0 -IdentityName 12345YourName.uEncrypt `
      -Publisher "CN=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" -PublisherDisplayName "Your Name"

.EXAMPLE
  # Local sideload test, signed with a self-signed certificate created on the fly.
  ./packaging/build-msix.ps1 -SelfSign
#>
param(
    [string]$Version = "0.1.0.0",
    [ValidateSet("x64", "arm64")]
    [string[]]$Architecture = @("x64"),
    [string]$IdentityName = "uencrypt.dev",
    [string]$Publisher = "CN=uencrypt-dev",
    [string]$PublisherDisplayName = "uencrypt developer",
    [string]$OutputDir = "artifacts/msix",
    [switch]$SelfSign
)

$ErrorActionPreference = "Stop"
$root = Resolve-Path (Join-Path $PSScriptRoot "..")
$gui = Join-Path $root "gui"

if ($Version -notmatch '^\d+\.\d+\.\d+\.0$') {
    throw "Version must look like 1.2.3.0 (the Store requires the last part to be 0)."
}
$appVersion = $Version -replace '\.0$', ''

function Find-SdkTool([string]$name) {
    $kits = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
    $tool = Get-ChildItem $kits -Recurse -Filter $name -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -match '\\x64\\' } |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $tool) { throw "$name not found. Install the Windows 10/11 SDK." }
    return $tool.FullName
}

$makeappx = Find-SdkTool "makeappx.exe"
New-Item -ItemType Directory -Force -Path (Join-Path $root $OutputDir) | Out-Null
$packages = @()

foreach ($arch in $Architecture) {
    $goarch = @{ x64 = "amd64"; arm64 = "arm64" }[$arch]
    $layout = Join-Path $root "artifacts/msix-layout/$arch"
    if (Test-Path $layout) { Remove-Item -Recurse -Force $layout }
    New-Item -ItemType Directory -Force -Path $layout | Out-Null

    Write-Host "Building windows/$goarch..."
    Push-Location $gui
    try {
        # -trimpath keeps build paths out of the binary; the version shows on the About page.
        wails build -clean -platform "windows/$goarch" -trimpath -o uencrypt-gui.exe `
            -ldflags "-X main.version=$appVersion"
        if ($LASTEXITCODE -ne 0) { throw "wails build failed" }
    } finally {
        Pop-Location
    }
    Copy-Item (Join-Path $gui "build/bin/uencrypt-gui.exe") $layout

    # Licence texts for everything shipped.
    Push-Location $root
    try {
        go run ./tools/notices -goos windows -goarch $goarch -npm gui/frontend `
            -o (Join-Path $layout "THIRD-PARTY-NOTICES.txt") ./gui
        if ($LASTEXITCODE -ne 0) { throw "Generating third-party notices failed" }
    } finally {
        Pop-Location
    }
    Copy-Item (Join-Path $root "LICENSE") (Join-Path $layout "LICENSE.txt")

    Copy-Item -Recurse (Join-Path $root "packaging/msix/Images") (Join-Path $layout "Images")
    (Get-Content (Join-Path $root "packaging/msix/AppxManifest.xml") -Raw) `
        -replace '\$\(IdentityName\)', $IdentityName `
        -replace '\$\(Publisher\)', $Publisher `
        -replace '\$\(PublisherDisplayName\)', $PublisherDisplayName `
        -replace '\$\(Version\)', $Version `
        -replace '\$\(Architecture\)', $arch |
        Set-Content -Encoding UTF8 (Join-Path $layout "AppxManifest.xml")

    $msix = Join-Path $root "$OutputDir/uEncrypt_${Version}_$arch.msix"
    & $makeappx pack /o /d $layout /p $msix
    if ($LASTEXITCODE -ne 0) { throw "makeappx failed" }
    $packages += $msix
    Write-Host "Created $msix"
}

if ($SelfSign) {
    $signtool = Find-SdkTool "signtool.exe"
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Subject -eq $Publisher } | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type Custom -Subject $Publisher -KeyUsage DigitalSignature `
            -FriendlyName "uencrypt dev signing" -CertStoreLocation Cert:\CurrentUser\My `
            -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.3", "2.5.29.19={text}")
    }
    foreach ($msix in $packages) {
        & $signtool sign /fd SHA256 /sha1 $cert.Thumbprint $msix
        if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
    }
    Write-Host ""
    Write-Host "Signed with self-signed '$Publisher'. To install locally, trust it once (admin PowerShell):"
    Write-Host "  Export-Certificate -Cert Cert:\CurrentUser\My\$($cert.Thumbprint) -FilePath uencrypt-dev.cer"
    Write-Host "  Import-Certificate -FilePath uencrypt-dev.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople"
}
