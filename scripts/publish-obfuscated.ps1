[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('win-x64', 'win-arm64')]
    [string]$RuntimeIdentifier,

    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$work = Join-Path $root "artifacts/obfuscation/$RuntimeIdentifier"
$publish = Join-Path $work 'publish'
$obfuscated = Join-Path $work 'obfuscated'
$config = Join-Path $work 'obfuscar.xml'
$output = [System.IO.Path]::GetFullPath($OutputDirectory)

if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    throw 'MSVC C++ Build Tools (cl.exe) are required to compile the native core.'
}
$nativeArchitecture = if ($RuntimeIdentifier -eq 'win-arm64') { 'ARM64' } else { 'X64' }
if ($env:VSCMD_ARG_TGT_ARCH -and $env:VSCMD_ARG_TGT_ARCH -ne $nativeArchitecture) {
    throw "The active MSVC developer environment targets $env:VSCMD_ARG_TGT_ARCH, but $RuntimeIdentifier requires $nativeArchitecture."
}

if (Test-Path $work) { Remove-Item $work -Recurse -Force }
New-Item $publish -ItemType Directory -Force | Out-Null
New-Item $obfuscated -ItemType Directory -Force | Out-Null
New-Item $output -ItemType Directory -Force | Out-Null

Push-Location $root
try {
    & dotnet tool restore
    if ($LASTEXITCODE -ne 0) { throw "dotnet tool restore failed: $LASTEXITCODE" }

    & dotnet publish SecRev.csproj -c Release -r $RuntimeIdentifier --self-contained false -o $publish -p:DebugType=None -p:DebugSymbols=false
    if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed: $LASTEXITCODE" }

    $publishXml = [System.Security.SecurityElement]::Escape($publish)
    $obfuscatedXml = [System.Security.SecurityElement]::Escape($obfuscated)
    @"
<?xml version="1.0" encoding="utf-8"?>
<Obfuscator>
  <Var name="InPath" value="$publishXml" />
  <Var name="OutPath" value="$obfuscatedXml" />
  <Var name="KeepPublicApi" value="true" />
  <Var name="HidePrivateApi" value="true" />
  <Var name="MarkedOnly" value="true" />
  <Var name="HideStrings" value="false" />
  <Var name="SkipGenerated" value="true" />
  <Var name="SkipSpecialName" value="true" />
  <Module file="$publishXml/SecRev.dll" />
</Obfuscator>
"@ | Set-Content -Path $config -Encoding utf8

    & dotnet tool run obfuscar.console -- $config
    if ($LASTEXITCODE -ne 0) { throw "Obfuscar failed: $LASTEXITCODE" }

    Copy-Item (Join-Path $publish '*') $output -Recurse -Force
    Copy-Item (Join-Path $obfuscated 'SecRev.dll') (Join-Path $output 'SecRev.dll') -Force
    Get-ChildItem $output -Recurse -File | Where-Object { $_.Extension -eq '.pdb' -or $_.Name -like 'Obfuscar*.xml' -or $_.Extension -eq '.map' } | Remove-Item -Force
    Write-Host "Obfuscated release published to $output"
    Write-Host "Keep private symbols and mapping from $work outside the distribution."
}
finally {
    Pop-Location
}
