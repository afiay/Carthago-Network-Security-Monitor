param(
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if ($NoBuild) {
    dotnet test DOTNET.sln --no-build
}
else {
    dotnet test DOTNET.sln
}
