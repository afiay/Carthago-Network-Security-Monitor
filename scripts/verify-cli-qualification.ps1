# SPDX-License-Identifier: MIT
# CLI-006E: owner-run, pinned portable qualification; optional Windows parity.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidatePattern('^[a-f0-9]{40}$')][string]$SourceSha,
    [switch]$AuthorizedTestTime,
    [switch]$IncludeWindowsParity
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $AuthorizedTestTime) { throw 'Requires owner-authorized test time for the selected SHA.' }
if ($IncludeWindowsParity -and $env:OS -ne 'Windows_NT') { throw 'Windows parity requires Windows and the .NET SDK.' }
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    function Assert-PinnedCheckout {
        $head = (& git rev-parse HEAD)
        if ($LASTEXITCODE -ne 0 -or $head -cne $SourceSha) { throw 'HEAD differs from selected SHA.' }
        $branch = (& git branch --show-current)
        if ($LASTEXITCODE -ne 0 -or ($branch -cne 'feature/carthago-reliability-hardening' -and ($branch -or $IncludeWindowsParity))) { throw 'Unexpected branch.' }
        $dirty = @(& git status --porcelain --untracked-files=all)
        if ($LASTEXITCODE -ne 0 -or $dirty.Count -ne 0) { throw 'Clean checkout required; preserve local edits before testing.' }
    }
    Assert-PinnedCheckout
    $runId = [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + $SourceSha.Substring(0,12) + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $dir = Join-Path $root ('build-verify/cli-qualification/' + $runId)
    New-Item -ItemType Directory -Path $dir | Out-Null
    $report = [ordered]@{
        schemaVersion=1; sourceSha=$SourceSha; startedUtc=[DateTime]::UtcNow.ToString('o')
        finishedUtc=$null; status='NotCompleted'; sdkVersion=$null
        platform=[System.Environment]::OSVersion.VersionString
        windowsParityRequested=[bool]$IncludeWindowsParity; stages=[ordered]@{}; suites=[ordered]@{}; replaySmoke=[ordered]@{}; perRuleReplay=[ordered]@{}
        portableSyntheticQualified=$false; windowsParityQualified=$false
        fieldAccuracyQualified=$false; liveCaptureQualified=$false; deploymentQualified=$false
        blocker=$null
    }
    function Invoke-Stage([string]$Name,[string[]]$Arguments) {
        Assert-PinnedCheckout
        $previous=$ErrorActionPreference
        $ErrorActionPreference='Continue'
        try {
            & dotnet @Arguments *> (Join-Path $dir ($Name + '.log'))
            $code=$LASTEXITCODE
        } finally { $ErrorActionPreference=$previous }
        $report.stages[$Name]=$code
        Assert-PinnedCheckout
        return $code
    }
    function Require-Stage([string]$Name,[string[]]$Arguments) {
        $code=Invoke-Stage $Name $Arguments
        if ($code -ne 0) { throw "Stage $Name failed (exit $code); inspect its log." }
    }
    function Invoke-TestSuite([string]$Name,[string]$Project,[string]$Filter,[hashtable]$RequiredClasses) {
        $trx=Join-Path $dir ($Name + '.trx')
        $arguments=@('test',$Project,'-c','Release','--no-build','--no-restore','--results-directory',$dir,'--logger',('trx;LogFileName=' + $Name + '.trx'))
        if ($Filter) { $arguments+=@('--filter',$Filter) }
        $code=Invoke-Stage $Name $arguments
        if (-not (Test-Path -LiteralPath $trx -PathType Leaf)) { throw "Suite $Name TRX missing (exit $code)." }
        [xml]$xml=Get-Content -LiteralPath $trx -Raw
        $counters=$xml.SelectSingleNode("//*[local-name()='ResultSummary']/*[local-name()='Counters']")
        if ($null -eq $counters) { throw "Suite $Name TRX counters missing." }
        $counts=[ordered]@{}
        foreach ($key in @('total','executed','passed','failed')) {
            $value=$counters.GetAttribute($key)
            if ($value -notmatch '^[0-9]+$') { throw "Suite $Name invalid TRX counter $key." }
            $counts[$key]=[int]$value
        }
        $classes=[ordered]@{}
        $report.suites[$Name]=[ordered]@{ counters=$counts; requiredClasses=$classes }
        # Map result test IDs to declared test classes, rather than inferring
        # coverage from source filenames or a passing aggregate counter.
        $byId=@{}
        foreach ($definition in $xml.SelectNodes("//*[local-name()='TestDefinitions']/*[local-name()='UnitTest']")) {
            $method=$definition.SelectSingleNode("*[local-name()='TestMethod']")
            if ($null -ne $method) { $byId[$definition.GetAttribute('id')]=$method.GetAttribute('className') }
        }
        foreach ($class in $RequiredClasses.Keys) { $classes[$class]=0 }
        foreach ($result in $xml.SelectNodes("//*[local-name()='Results']/*[local-name()='UnitTestResult']")) {
            if ($result.GetAttribute('outcome') -cne 'Passed') { continue }
            $id=$result.GetAttribute('testId')
            if (-not $byId.ContainsKey($id)) { throw "Suite $Name passed result has no test definition." }
            $className=($byId[$id] -split ',')[0].Trim()
            if ($RequiredClasses.ContainsKey($className)) { $classes[$className]++ }
        }
        if ($code -ne 0 -or $counts.total -le 0 -or $counts.total -ne $counts.executed -or
            $counts.total -ne $counts.passed -or $counts.failed -ne 0) { throw "Suite $Name incomplete or nonpassing (exit $code)." }
        foreach ($class in $RequiredClasses.Keys) {
            if ($classes[$class] -lt $RequiredClasses[$class]) { throw "Suite $Name missing required passed cases for $class." }
        }
    }
    # Synthetic raw IPv4/TCP fixtures only. No capture device or real traffic.
    function New-SmokeFrame([string]$Uri,[uint32]$Sequence,[string]$Method='GET',
        [string]$Agent='', [bool]$Reverse=$false,[byte]$Flags=0x18,[uint32]$Ack=0,[uint16]$ServerPort=7001) {
        $headers="Host: example.test`r`n"
        if ($Agent -ne '') { $headers+="User-Agent: $Agent`r`n" }
        [byte[]]$payload=@()
        if ($Uri -ne '') { $payload=[Text.Encoding]::ASCII.GetBytes("$Method $Uri HTTP/1.1`r`n$headers`r`n") }
        [byte[]]$frame=New-Object byte[] (40+$payload.Length)
        $frame[0]=0x45; $frame[8]=64; $frame[9]=6
        $frame[2]=[byte]($frame.Length -shr 8); $frame[3]=[byte]($frame.Length -band 255)
        [byte[]]$addresses=if ($Reverse) { @(198,51,100,2,192,0,2,1) } else { @(192,0,2,1,198,51,100,2) }
        [Array]::Copy($addresses,0,$frame,12,8)
        $src=if ($Reverse) { $ServerPort } else { 51000 }
        $dst=if ($Reverse) { 51000 } else { $ServerPort }
        $frame[20]=[byte]($src -shr 8); $frame[21]=[byte]($src -band 255)
        $frame[22]=[byte]($dst -shr 8); $frame[23]=[byte]($dst -band 255)
        $frame[24]=[byte](($Sequence -shr 24) -band 255)
        $frame[25]=[byte](($Sequence -shr 16) -band 255)
        $frame[26]=[byte](($Sequence -shr 8) -band 255)
        $frame[27]=[byte]($Sequence -band 255)
        $frame[28]=[byte](($Ack -shr 24) -band 255)
        $frame[29]=[byte](($Ack -shr 16) -band 255)
        $frame[30]=[byte](($Ack -shr 8) -band 255)
        $frame[31]=[byte]($Ack -band 255)
        $frame[32]=0x50; $frame[33]=$Flags
        [Array]::Copy($payload,0,$frame,40,$payload.Length)
        return ,$frame
    }
    function New-SmokeCapture([string]$Path,[bool]$Ng) {
        $uris=@('/wp-content/plugins/wp2shell_test/file.php','/SetupWizard.aspx/next',
            '/LogoImageHandler.ashx?clazz=example','/config/keystore/test.jsp',
            '/?search=%00{.cmd.exe','/wp-content/plugins/wp2shell_test/file.php',
            '/LogoImageHandler.ashx?class=example')
        $frames=[System.Collections.Generic.List[byte[]]]::new()
        [uint32]$sequence=0
        foreach ($uri in $uris) {
            [byte[]]$frame=New-SmokeFrame $uri $sequence
            $frames.Add($frame)
            $sequence += [uint32]($frame.Length-40)
        }
        Write-SmokeCapture $Path $Ng $frames
    }
    function Write-SmokeCapture([string]$Path,[bool]$Ng,[System.Collections.Generic.List[byte[]]]$Frames) {
        $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        $writer=[IO.BinaryWriter]::new($stream)
        try {
            if ($Ng) {
                # Section header (28 bytes), then one RAW IPv4 interface (20 bytes).
                $writer.Write([uint32]0x0a0d0d0a);$writer.Write([uint32]28)
                $writer.Write([uint32]0x1a2b3c4d);$writer.Write([uint16]1);$writer.Write([uint16]0)
                $writer.Write([int64]-1);$writer.Write([uint32]28)
                $writer.Write([uint32]1);$writer.Write([uint32]20)
                $writer.Write([uint16]101);$writer.Write([uint16]0);$writer.Write([uint32]65535)
                $writer.Write([uint32]20)
            } else {
                $writer.Write([uint32]2712847316);$writer.Write([uint16]2);$writer.Write([uint16]4)
                $writer.Write([uint32]0);$writer.Write([uint32]0);$writer.Write([uint32]65535);$writer.Write([uint32]101)
            }
            for ($i=0;$i -lt $Frames.Count;$i++) {
                [byte[]]$frame=$Frames[$i]
                $seconds=[uint32](100+$i)
                if ($Ng) {
                    $padding=(4-($frame.Length % 4)) % 4
                    $length=[uint32](32+$frame.Length+$padding)
                    $writer.Write([uint32]6);$writer.Write($length);$writer.Write([uint32]0)
                    $writer.Write([uint32]0);$writer.Write([uint32]($seconds*1000000))
                    $writer.Write([uint32]$frame.Length);$writer.Write([uint32]$frame.Length)
                    $writer.Write($frame)
                    if ($padding -gt 0) { $writer.Write([byte[]](New-Object byte[] $padding)) }
                    $writer.Write($length)
                } else {
                    $writer.Write($seconds);$writer.Write([uint32]0)
                    $writer.Write([uint32]$frame.Length);$writer.Write([uint32]$frame.Length);$writer.Write($frame)
                }
            }
        } finally { $writer.Dispose();$stream.Dispose() }
    }
    function Invoke-ReplaySmoke([string]$Cli,[string]$Format) {
        $fixture=Join-Path $dir ("synthetic."+$Format)
        New-SmokeCapture $fixture ($Format -ceq 'pcapng')
        $stage="cli-replay-"+$Format
        Require-Stage $stage @($Cli,'pcap','detect',$fixture,'--rules','R586,R587,R588,R589,R590,R1000','--limit','10','--json')
        $raw=Get-Content -LiteralPath (Join-Path $dir ($stage+'.log')) -Raw
        $rootJson=$raw | ConvertFrom-Json
        $replay=$rootJson.replay
        if ($rootJson.schemaVersion -ne 1 -or $rootJson.mode -cne 'offline_replay' -or
            $rootJson.provenance -cne 'untrusted_capture' -or $rootJson.detectionValidation -cne 'not_assessed' -or
            $replay.format -cne $Format -or $replay.packetsRead -ne 7 -or $replay.parsed -ne 7 -or
            $replay.rejected -ne 0 -or $replay.captureTruncated -ne 0 -or $replay.clockResets -ne 0 -or
            $replay.matchCount -ne 5 -or $replay.suppressedCount -ne 1 -or $replay.findingsTruncated -ne $false -or
            @($replay.findings).Count -ne 5 -or @($replay.rules).Count -ne 6 -or $raw.Contains('cmd.exe')) {
            throw "Executable replay smoke mismatch for $Format."
        }
        $ids=@('R586','R587','R588','R589','R590')
        for ($i=0;$i -lt $ids.Count;$i++) {
            $rule=$replay.rules[$i];$finding=$replay.findings[$i]
            $suppressed=if ($i -eq 0) { 1 } else { 0 }
            if ($rule.ruleId -cne $ids[$i] -or $rule.status -cne 'evaluated' -or
                $rule.evaluated -ne 7 -or $rule.matches -ne 1 -or $rule.suppressed -ne $suppressed -or
                $finding.ruleId -cne $ids[$i] -or $finding.packetNumber -ne ($i+1) -or $finding.method -cne 'GET') {
                throw "Executable replay per-rule mismatch for $Format."
            }
        }
        $unsupported=$replay.rules[5]
        if ($unsupported.ruleId -cne 'R1000' -or $unsupported.status -cne 'unsupported_detector' -or
            $unsupported.evaluated -ne 0 -or $unsupported.matches -ne 0 -or $unsupported.suppressed -ne 0) {
            throw "Executable replay unsupported-rule mismatch for $Format."
        }
        $report.replaySmoke[$Format]=[ordered]@{
            fixtureSha256=(Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
            packetsRead=$replay.packetsRead; parsed=$replay.parsed; matches=$replay.matchCount
            suppressed=$replay.suppressedCount; supportedRuleIds=$ids; unsupportedRuleId='R1000'
        }
    }
    # Independent positive and near-miss fixtures, selected from existing detector tests.
    # Each invocation has a fresh replay dispatcher; R601 requires SYN/SYN-ACK provenance.
    function Invoke-PerRuleReplay([string]$Cli,[string]$Format) {
        $cases=@(
            ,@('R586','GET','/wp-content/plugins/wp2shell_test/file.php','/wp-content/plugins/wp2shell/file.php','','')
            ,@('R587','GET','/SetupWizard.aspx/next','/SetupWizard.aspx','','')
            ,@('R588','GET','/LogoImageHandler.ashx?clazz=example','/LogoImageHandler.ashx?class=example','','')
            ,@('R589','GET','/config/keystore/test.jsp','/config/keystore/test.txt','','')
            ,@('R590','GET','/?search=%00{.cmd.exe','/?search=%00{.example','','')
            ,@('R591','GET','/ServletApi/../RestApi/LogonCustomization','/ServletApi/RestApi/LogonCustomization','','')
            ,@('R592','GET','/test.html?dwn=example&fn=sample','/test.html?dwn=example','','')
            ,@('R593','GET','/?doAs=`example`','/?doAs=example','','')
            ,@('R594','GET','/rest/api/latest/projects/test?prefix=%00--exec','/rest/api/latest/projects/test?prefix=example','','')
            ,@('R595','GET','/public/plugins/graph/../../../../example','/public/plugins/graph/../../../example','','')
            ,@('R596','GET','/cgi-bin/jarrewrite.sh','/cgi-bin/jarrewrite.sh','() { example','Mozilla')
            ,@('R597','GET','/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini%00','/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini','','')
            ,@('R598','GET','/?file=C:/Users/example','/?file=D:/Users/example','','')
            ,@('R599','GET','/apply_abstract.cgi?file=..%2fexample','/images/apply_abstract.cgi?file=..%2fexample','','')
            ,@('R600','POST','/owa/auth/Current/themes/resources/example','/owa/auth/Current/themes/other/example','','')
            ,@('R601','POST','/?cmd=connect','/?cmd=connect','','Mozilla')
            ,@('R602','GET','/SolarWinds/api/WebResource.axd','/SolarWinds/api/css.i18n.ashx','','')
            ,@('R603','GET','/?handle=com.bea.console.handles.JndiBindingHandle&ref=ldap://example.test&server=AdminServer','/?handle=com.bea.console.handles.JndiBindingHandle&ref=ldap://example.test','','')
            ,@('R604','GET','/ecp/test?__VIEWSTATE=example','/ecp/test?viewstate=example','','')
            ,@('R605','POST','/upload.action?filename=../../../../example','/upload.action?filename=../../../example','','')
        )
        $report.perRuleReplay[$Format]=[ordered]@{}
        foreach ($case in $cases) {
            $id=$case[0]; $method=$case[1]
            foreach ($kind in @('positive','negative')) {
                $positive=$kind -ceq 'positive'
                $uri=if ($positive) { $case[2] } else { $case[3] }
                $agent=if ($positive) { $case[4] } else { $case[5] }
                $frames=[System.Collections.Generic.List[byte[]]]::new()
                if ($id -ceq 'R601') {
                    $frames.Add((New-SmokeFrame '' 100 -Flags 2 -ServerPort 80))
                    $frames.Add((New-SmokeFrame '' 500 -Reverse $true -Flags 0x12 -Ack 101 -ServerPort 80))
                    $frames.Add((New-SmokeFrame $uri 101 -Method $method -Agent $agent -Ack 501 -ServerPort 80))
                } else {
                    $frames.Add((New-SmokeFrame $uri 0 -Method $method -Agent $agent))
                }
                $stage="cli-paired-$Format-$id-$kind"
                $fixture=Join-Path $dir ($stage+'.'+$Format)
                Write-SmokeCapture $fixture ($Format -ceq 'pcapng') $frames
                Require-Stage $stage @($Cli,'pcap','detect',$fixture,'--rules',$id,'--limit','10','--json')
                $raw=Get-Content -LiteralPath (Join-Path $dir ($stage+'.log')) -Raw
                $json=$raw | ConvertFrom-Json
                $replay=$json.replay
                $expectedMatches=if ($positive) { 1 } else { 0 }
                if ($json.schemaVersion -ne 1 -or $json.mode -cne 'offline_replay' -or
                    $json.provenance -cne 'untrusted_capture' -or $json.detectionValidation -cne 'not_assessed' -or
                    $replay.format -cne $Format -or $replay.packetsRead -ne $frames.Count -or
                    $replay.parsed -ne $frames.Count -or $replay.rejected -ne 0 -or
                    $replay.captureTruncated -ne 0 -or $replay.clockResets -ne 0 -or
                    $replay.matchCount -ne $expectedMatches -or $replay.suppressedCount -ne 0 -or
                    $replay.findingsTruncated -ne $false -or @($replay.findings).Count -ne $expectedMatches -or
                    @($replay.rules).Count -ne 1 -or $replay.rules[0].ruleId -cne $id -or
                    $replay.rules[0].status -cne 'evaluated' -or $replay.rules[0].evaluated -ne $frames.Count -or
                    $replay.rules[0].matches -ne $expectedMatches -or $replay.rules[0].suppressed -ne 0) {
                    throw "Per-rule executable replay mismatch: $Format $id $kind."
                }
                if ($positive -and ($replay.findings[0].ruleId -cne $id -or
                    $replay.findings[0].method -cne $method -or $replay.findings[0].packetNumber -ne $frames.Count)) {
                    throw "Per-rule executable finding mismatch: $Format $id."
                }
                $report.perRuleReplay[$Format]["$id-$kind"]=[ordered]@{
                    fixtureSha256=(Get-FileHash -LiteralPath $fixture -Algorithm SHA256).Hash.ToLowerInvariant()
                    outputSha256=(Get-FileHash -LiteralPath (Join-Path $dir ($stage+'.log')) -Algorithm SHA256).Hash.ToLowerInvariant()
                    ruleId=$id; control=$kind; packets=$frames.Count; matches=$replay.matchCount; suppressed=$replay.suppressedCount
                }
            }
        }
        if ($report.perRuleReplay[$Format].Count -ne 40) { throw "Incomplete paired matrix: $Format." }
    }
    try {
        Require-Stage 'sdk-version' @('--version')
        $report.sdkVersion=(Get-Content -LiteralPath (Join-Path $dir 'sdk-version.log') -Raw).Trim()
        Require-Stage 'portable-build' @('build','Carthago.Cli.Tests/Carthago.Cli.Tests.csproj','-c','Release','--no-incremental','--nologo')
        Invoke-TestSuite 'portable-tests' 'Carthago.Cli.Tests/Carthago.Cli.Tests.csproj' '' @{
            'Carthago.Cli.Tests.PortableMonitorSessionTests'=10
            'Carthago.Cli.Tests.PortableCaptureRunTests'=10
            'Carthago.Cli.Tests.PortableBufferedCaptureTests'=12
            'Carthago.Cli.Tests.NativeCaptureDiscoveryTests'=12
            'Carthago.Cli.Tests.NativePcapCaptureSourceTests'=22
            'Carthago.Cli.Tests.NativeCaptureQualificationTests'=10
            'Carthago.Cli.Tests.PortableMonitorCommandTests'=21
            'Carthago.Cli.Tests.PortableMonitorControlTests'=10
            'Carthago.Cli.Tests.PortableMonitorJournalTests'=12
            'Carthago.Cli.Tests.PortableReplayTests'=15
            'Carthago.Cli.Tests.PortableHttp602605Tests'=24
            'Carthago.Cli.Tests.PortableHttp596600Tests'=29
            'Carthago.Cli.Tests.PortableHttp591595Tests'=25
            'Carthago.Cli.Tests.PortableRuleCapabilityTests'=10
            'Carthago.Cli.Tests.PortableHttpBatchTests'=18
            'Carthago.Cli.Tests.PortableR587Tests'=7
            'Carthago.Cli.Tests.PortableR589Tests'=11
            'Carthago.Cli.Tests.PortablePcapInspectionTests'=1
            'Carthago.Cli.Tests.PortablePcapNgTests'=1
            'Carthago.Cli.Tests.CliApplicationTests'=1
        }
        # Exercise the built executable entry point, not only the in-process API.
        $cli=Join-Path $root 'Carthago.Cli/bin/Release/net8.0/carthago.dll'
        if (-not (Test-Path -LiteralPath $cli -PathType Leaf)) { throw 'Built CLI assembly missing.' }
        Require-Stage 'cli-capabilities' @($cli,'rules','capabilities','--json')
        $catalog=Get-Content -LiteralPath (Join-Path $dir 'cli-capabilities.log') -Raw | ConvertFrom-Json
        $expected=@('R586','R587','R588','R589','R590','R591','R592','R593','R594','R595','R596','R597','R598','R599','R600','R601','R602','R603','R604','R605')
        $actual=@($catalog.rules | ForEach-Object { $_.ruleId })
        if ($catalog.schemaVersion -ne 1 -or $catalog.scope -cne 'compiled_portable_catalog' -or
            $catalog.detectionValidation -cne 'not_assessed' -or $catalog.supportedCount -ne $expected.Count -or
            ($actual -join ',') -cne ($expected -join ',')) { throw 'CLI capability smoke contract mismatch.' }
        Require-Stage 'cli-unsupported' @($cli,'rules','capabilities','R1000','--json')
        $unsupported=Get-Content -LiteralPath (Join-Path $dir 'cli-unsupported.log') -Raw | ConvertFrom-Json
        if (@($unsupported.rules).Count -ne 1 -or $unsupported.rules[0].ruleId -cne 'R1000' -or
            $unsupported.rules[0].status -cne 'unsupported_detector' -or
            $unsupported.rules[0].registration -cne 'not_assessed') { throw 'CLI unsupported smoke contract mismatch.' }
        Invoke-ReplaySmoke $cli 'pcap'
        Invoke-ReplaySmoke $cli 'pcapng'
        Invoke-PerRuleReplay $cli 'pcap'
        Invoke-PerRuleReplay $cli 'pcapng'
        $report.portableSyntheticQualified=$true
        if ($IncludeWindowsParity) {
            Require-Stage 'windows-build' @('build','Carthago.Tests/Carthago.Tests.csproj','-c','Release','--no-incremental','--nologo')
            Invoke-TestSuite 'windows-parity' 'Carthago.Tests/Carthago.Tests.csproj' 'FullyQualifiedName~PortableR587ParityTests|FullyQualifiedName~PortableR589ParityTests|FullyQualifiedName~PortableHttpBatchParityTests|FullyQualifiedName~PortableHttp591595ParityTests|FullyQualifiedName~PortableHttp596600ParityTests|FullyQualifiedName~PortableHttp602605ParityTests|FullyQualifiedName~R601HeaderCaptureTests' @{
                'Carthago.Tests.PortableR587ParityTests'=4
                'Carthago.Tests.PortableR589ParityTests'=4
                'Carthago.Tests.PortableHttpBatchParityTests'=15
                'Carthago.Tests.PortableHttp591595ParityTests'=20
                'Carthago.Tests.PortableHttp596600ParityTests'=24
                'Carthago.Tests.PortableHttp602605ParityTests'=20
                'Carthago.Tests.R601HeaderCaptureTests'=16
            }
            $report.windowsParityQualified=$true
        }
        Assert-PinnedCheckout
        $report.status=if ($IncludeWindowsParity) { 'SyntheticPortableAndWindowsParityPassed' } else { 'SyntheticPortablePassed' }
    } catch {
        $report.status='Failed';$report.blocker=$_.Exception.Message
        throw
    } finally {
        $report.finishedUtc=[DateTime]::UtcNow.ToString('o')
        $report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $dir 'qualification.json') -Encoding UTF8
        Write-Host "CLI qualification report: $dir"
    }
} finally { Pop-Location }
