[CmdletBinding()]
param(
    [switch]$ServicesOnly,
    [switch]$Stop
)

$ErrorActionPreference = 'Stop'
$projectName = 'secrev-local-pdf'
$composeFile = Join-Path $PSScriptRoot 'docker-compose.local.yml'

if ($ServicesOnly -and $Stop) {
    throw 'Use either -ServicesOnly or -Stop, not both.'
}

$docker = Get-Command docker -ErrorAction SilentlyContinue
if ($null -eq $docker) {
    throw 'Docker Desktop with the Linux container engine and Docker Compose is required for local PDF services on Windows.'
}

# The app passes an ephemeral per-session token. Generate one for manual use only.
if ([string]::IsNullOrWhiteSpace($env:PDF_SANDBOX_TOKEN)) {
    $bytes = [System.Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
    $env:PDF_SANDBOX_TOKEN = [Convert]::ToHexString($bytes)
    [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
}
if ($env:PDF_SANDBOX_TOKEN.Length -lt 32) {
    throw 'PDF_SANDBOX_TOKEN must contain at least 32 characters.'
}

function Invoke-Compose([string[]]$ComposeArgs) {
    & $docker.Source compose --project-name $projectName --file $composeFile @ComposeArgs
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose failed with exit code $LASTEXITCODE. Confirm Docker Desktop is running and configured for Linux containers."
    }
}

if ($Stop) {
    Invoke-Compose @('down', '--remove-orphans')
    exit 0
}

& $docker.Source info *> $null
if ($LASTEXITCODE -ne 0) {
    throw 'Docker is installed but its Linux engine is not running or accessible.'
}

$started = $false
try {
    Write-Host 'Building and starting the local PDF parser and ClamAV containers...'
    $started = $true
    Invoke-Compose @('up', '--build')
}
finally {
    # Also stop the Compose project on normal exit or Ctrl+C. The desktop also
    # issues an explicit stop when closing the app in case this process is killed.
    if ($started) {
        try { Invoke-Compose @('down', '--remove-orphans') } catch { Write-Warning $_ }
    }
}
