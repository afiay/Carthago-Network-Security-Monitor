# SPDX-License-Identifier: MIT
# Operator-invoked Windows GA verification only. This script never executes
# automatically and never mutates detection rules, holdout or replay labels.
[CmdletBinding()]
param([switch]$TargetedOnly)

$ErrorActionPreference = "Stop"
$branch = "feature/carthago-reliability-hardening"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    $actualBranch = git branch --show-current
    if ($LASTEXITCODE -ne 0 -or $actualBranch -ne $branch) {
        throw "Expected branch $branch; found $actualBranch"
    }

    $dirty = @(git status --porcelain)
    if ($LASTEXITCODE -ne 0 -or $dirty.Count -gt 0) {
        throw "Working tree must be clean before verification."
    }

    git pull --ff-only origin $branch
    if ($LASTEXITCODE -ne 0) { throw "Fast-forward pull failed." }

    $sha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $sha.Length -ne 40) {
        throw "Could not establish exact tested SHA."
    }
    Write-Host "CARTHAGO Redis Software audit GA candidate SHA: $sha"

    dotnet build -c Release
    if ($LASTEXITCODE -ne 0) {
        throw "Release compilation failed; do NOT run --no-build against stale binaries."
    }

    $run = Get-Date -Format "yyyyMMdd-HHmmss"
    $dir = Join-Path $root ("build-verify/redis-audit-ga-" + $run)
    New-Item -ItemType Directory -Force -Path $dir | Out-Null

    $filters = @(
        "FullyQualifiedName~RedisSoftwareAuditSourceTests"
        "FullyQualifiedName~RedisAuditMutualTlsRelayReceiverTests"
        "FullyQualifiedName~RedisAuditSinkMetricsHealthTests"
        "FullyQualifiedName~RedisRespCaptureIntegrationTests"
        "FullyQualifiedName~RedisTrustedAuditCandidateGateTests"
        "FullyQualifiedName~TrustedAuditReceiptVerifierTests"
        "FullyQualifiedName~TrustedAuditReceiptCorrelationTests"
        "FullyQualifiedName~R561AdvancedAccuracyBatchTests"
        "FullyQualifiedName~R562AdvancedAccuracyBatchTests"
    ) -join "|"

    dotnet test Carthago.Tests/Carthago.Tests.csproj `
        -c Release --no-build `
        --filter $filters `
        --logger "trx;LogFileName=redis-source-targeted.trx" `
        --results-directory $dir

    if ($LASTEXITCODE -ne 0) {
        throw "Targeted Redis audit GA verification FAILED. Exact SHA: $sha"
    }
    Write-Host "Targeted Redis audit GA tests GREEN at $sha"

    if (-not $TargetedOnly) {
        dotnet test Carthago.Tests/Carthago.Tests.csproj `
            -c Release --no-build `
            --logger "trx;LogFileName=full-regression.trx" `
            --results-directory $dir
        if ($LASTEXITCODE -ne 0) {
            throw "Full xUnit regression FAILED or ABORTED. Exact SHA: $sha"
        }
        Write-Host "Full xUnit regression GREEN at $sha"
    }
    else {
        Write-Host "TargetedOnly selected: FULL regression NOT RUN and NOT VERIFIED."
    }

    $finalSha = (git rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $finalSha -ne $sha) {
        throw "HEAD moved during validation: invalid exact-SHA provenance."
    }

    Write-Host "Results directory: $dir"
    Write-Host "Verified source SHA: $sha"
    Write-Host "Scope: synthetic source contracts and xUnit only; no external detection-quality approval."
}
finally {
    Pop-Location
}
