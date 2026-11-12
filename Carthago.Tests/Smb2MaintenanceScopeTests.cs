// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;
using Xunit;

namespace Carthago.Tests;

public sealed class Smb2MaintenanceScopeTests
{
    private static readonly DateTime Epoch=new(2026,11,13,12,0,0,DateTimeKind.Utc);
    private const string Source="10.77.1.20", Destination="10.77.2.40";
    private static Smb2MaintenanceScope Scope(string id="R910")=>new()
    {
        ChangeId="CHG-Q8-001",RuleId=id,SourceIp=Source,DestinationIp=Destination,
        ProcessName="powershell.exe",ShareKind="administrative-disk",FileKind="script",
        StartsUtc=Epoch.AddMinutes(-2),EndsUtc=Epoch.AddMinutes(10)
    };
    private static EnvironmentTuningOptions Options(params Smb2MaintenanceScope[] scopes)
    {
        var options=new EnvironmentTuningOptions();
        options.Approved.AdminHosts.Add(Source);
        options.Approved.Smb2MaintenanceScopes.AddRange(scopes);
        return options;
    }
    private static async Task<(EvidenceDrivenPrecisionRuleBase Rule, DetectionEvent Event, TrafficRecord Write)> Candidate(string id)
    {
        var chain=Smb2CaptureQualificationTests.TargetChain("ADMIN$","deployment.ps1",source:Source,destination:Destination);
        var w=chain.Write;
        w.ProcessName="powershell.exe";w.ProcessId=817;w.ProcessAttribution="TcpSocketTable";
        w.SrcIsLocalHost=true;w.DstIsLocalHost=false;
        Assert.Equal("administrative-disk",w.Smb2WriteShareKind);
        Assert.Equal("script",w.Smb2WriteFileKind);
        EvidenceDrivenPrecisionRuleBase rule=id=="R910"?new R910_PowershellLdapSynThenSmbWriteRule()
            :new R950_PowershellPrivateScriptGetThenSmbWriteRule();
        var first=new TrafficRecord{Id=Guid.NewGuid(),Source=Source,Destination=Destination,
            SourcePort=53078,DestinationPort=id=="R910"?389:80,IpVersion=4,IsTcp=true,Protocol="TCP",
            TcpFlags=id=="R910"?(ushort)0x02:(ushort)0x18,Length=id=="R910"?40:240,
            L4Len=id=="R910"?0:200,ProcessName=w.ProcessName,ProcessId=w.ProcessId};
        if(id=="R950")
        {
            first.ApplicationProtocol="HTTP";first.HttpMethod="GET";first.HttpHost="deployment.example.test";
            first.HttpUri="/packages/setup.ps1";
        }
        Assert.False((await rule.EvaluateAsync(new RuleEvaluationContext(first,Sensitivity.Balanced,Epoch.AddSeconds(-3)))).Matched);
        var result=await rule.EvaluateAsync(new RuleEvaluationContext(w,Sensitivity.Balanced,Epoch));
        Assert.True(result.Matched);
        return(rule,Assert.Single(result.Events),w);
    }

    [Theory]
    [InlineData("R910")]
    [InlineData("R950")]
    public async Task ConfiguredScopeAnnotatesWithoutChangingDetectionOrPromoting(string id)
    {
        var (rule,evt,w)=await Candidate(id);
        var registry=new ApprovedAssetRegistry(Options(Scope(id)));
        var before=evt.ConfidenceScore;
        var approved=registry.Evaluate(id,evt,w,"Research");
        Assert.NotNull(approved);
        Assert.Equal(ApprovedAssetDisposition.Shadow,approved!.Disposition);
        Assert.Equal("CHG-Q8-001",approved.MatchedValue);
        var tuned=RuleTuningCatalog.Resolve("Research",rule.Descriptor,evt,w,registry);
        Assert.Equal(RuleMode.Shadow,tuned.EffectiveMode);
        Assert.Contains(RuleTuningReason.ApprovedAssetMatched,tuned.Reasons);
        Assert.Contains(tuned.ReasonDetails,d=>d.Contains("authorization not verified",StringComparison.Ordinal));
        Assert.Equal(before,evt.ConfidenceScore);
        Assert.False(RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor,evt,w,RuleMode.Alert,"Research",registry).AllowsAlert);
        Assert.Null(new ApprovedAssetRegistry(Options()).Evaluate(id,evt,w,"Research"));
    }

    [Theory]
    [InlineData("source")]
    [InlineData("destination")]
    [InlineData("rule")]
    [InlineData("process")]
    [InlineData("share")]
    [InlineData("file")]
    [InlineData("before-window")]
    [InlineData("expired")]
    [InlineData("partial-window")]
    [InlineData("nonlocal")]
    [InlineData("unknown-destination-locality")]
    [InlineData("attribution")]
    [InlineData("packet")]
    [InlineData("missing-create")]
    [InlineData("missing-admin")]
    [InlineData("duplicate")]
    [InlineData("overlap")]
    [InlineData("invalid-window")]
    [InlineData("wildcard")]
    public async Task InvalidOrAmbiguousScopeNeverAnnotates(string variant)
    {
        var (rule,evt,w)=await Candidate("R910");
        var scope=Scope(); var options=Options(scope);
        switch(variant)
        {
            case "source": scope=scope with{SourceIp="10.77.1.21"};break;
            case "destination": scope=scope with{DestinationIp="10.77.2.41"};break;
            case "rule": scope=scope with{RuleId="R950"};break;
            case "process": scope=scope with{ProcessName="pwsh.exe"};break;
            case "share": scope=scope with{ShareKind="other-disk"};break;
            case "file": scope=scope with{FileKind="executable"};break;
            case "before-window": scope=scope with{StartsUtc=Epoch.AddSeconds(1)};break;
            case "expired": scope=scope with{EndsUtc=Epoch};break;
            case "partial-window": scope=scope with{StartsUtc=Epoch.AddSeconds(-44)};break;
            case "nonlocal": w.SrcIsLocalHost=false;break;
            case "unknown-destination-locality": w.DstIsLocalHost=null;break;
            case "attribution": w.ProcessAttribution="CaptureProvided";break;
            case "packet": evt.PacketId=Guid.NewGuid().ToString("N");break;
            case "missing-create": w.Smb2WriteCreateCorrelationId=null;break;
            case "invalid-window": scope=scope with{EndsUtc=Epoch.AddHours(9)};break;
            case "wildcard": scope=scope with{SourceIp="10.77.1.0/24"};break;
        }
        options.Approved.Smb2MaintenanceScopes.Clear();
        options.Approved.Smb2MaintenanceScopes.Add(scope);
        if(variant=="missing-admin")options.Approved.AdminHosts.Clear();
        if(variant=="duplicate")options.Approved.Smb2MaintenanceScopes.Add(scope);
        if(variant=="overlap")options.Approved.Smb2MaintenanceScopes.Add(scope with{ChangeId="CHG-Q8-002"});
        var registry=new ApprovedAssetRegistry(options);
        Assert.Null(registry.Evaluate("R910",evt,w,"Research"));
        var tuned=RuleTuningCatalog.Resolve("Research",rule.Descriptor,evt,w,registry);
        Assert.DoesNotContain(RuleTuningReason.ApprovedAssetMatched,tuned.Reasons);
        Assert.False(RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor,evt,w,RuleMode.Alert,"Research",registry).AllowsAlert);
    }

    [Fact]
    public async Task SnapshotAndOtherRulesCannotInheritApproval()
    {
        var (_,evt,w)=await Candidate("R910");
        var options=Options(Scope());
        var registry=new ApprovedAssetRegistry(options);
        options.Approved.Smb2MaintenanceScopes.Clear();
        Assert.NotNull(registry.Evaluate("R910",evt,w,"Research"));
        foreach(var id in new[]{"R903","R908","R919","R942","R950"})
            Assert.Null(registry.Evaluate(id,evt,w,"Research"));
    }
}
