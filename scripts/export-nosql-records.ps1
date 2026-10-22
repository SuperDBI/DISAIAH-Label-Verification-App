[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$CustodianBundle,

    [Parameter(Mandatory = $true, Position = 1)]
    [string]$NewOutputDirectory,

    [Parameter(Mandatory = $true, Position = 2)]
    [guid]$TenantId
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$project = Join-Path $root 'tools/SecRev.NoSqlExport/SecRev.NoSqlExport.csproj'

if (-not (Test-Path -LiteralPath $CustodianBundle -PathType Container)) {
    throw 'CustodianBundle must be an existing exported SecRev bundle directory.'
}
if (Test-Path -LiteralPath $NewOutputDirectory) {
    throw 'NewOutputDirectory must not exist; conversion refuses to overwrite data.'
}

& dotnet run --project $project -- $CustodianBundle $NewOutputDirectory $TenantId
if ($LASTEXITCODE -ne 0) {
    throw "Validated record conversion failed (exit code $LASTEXITCODE). No partial output should be retained."
}
