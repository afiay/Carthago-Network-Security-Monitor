param(
    [switch]$NoRestore
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not $NoRestore) {
    dotnet restore DOTNET.sln
}

dotnet build DOTNET.sln --no-restore
