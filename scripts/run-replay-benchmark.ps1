param(
    [string]$ReplayDirectory = "Tests/RuleReplaySamples",
    [string]$OutputDirectory = "build-verify",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not $NoBuild) {
    dotnet build Carthago.Benchmarks\Carthago.Benchmarks.csproj --no-restore
}

dotnet run --project Carthago.Benchmarks\Carthago.Benchmarks.csproj --no-build -- --replay-dir $ReplayDirectory --output-dir $OutputDirectory
