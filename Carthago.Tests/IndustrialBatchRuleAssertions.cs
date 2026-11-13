// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;

internal static class IndustrialBatchRuleAssertions
{
    private static RuleEvaluationContext At(TrafficRecord r,int seconds)
        => new(r,Sensitivity.Balanced,IndustrialBatchWireFixtures.Epoch.AddSeconds(seconds));
    internal static IDetectionRule[] AllRules()=>new IDetectionRule[]
    {
        new R988_PublicBacnetDeviceSystemStatusReadRule(),
        new R989_PublicBacnetDeviceAllPropertiesReadRule(),
        new R990_PublicBacnetInputOutOfServiceRule(),
        new R991_PublicBacnetAtomicFileReadRule(),
        new R992_PublicBacnetAtomicFileWriteRule(),
        new R993_PublicFinsCpuStatusReadRule(),
        new R994_PublicFinsBulkDataMemoryReadRule(),
        new R995_PublicDnp3IntegrityReadRule(),
        new R996_PublicDnp3AbsoluteTimeWriteRule(),
        new R997_PublicModbusReadWriteSamePairZeroRule(),
        new R998_PublicModbusBulkFileWriteRule(),
        new R999_PublicSnmpInterfaceAdminDownRule(),
        new R1000_PublicSnmpIpv4ForwardingDisableRule(),
    };
    internal static async Task Positive(IDetectionRule rule,IndustrialBatchOperation op,int port,bool tcp,bool same,string hex)
    {
        var data=IndustrialBatchWireFixtures.Decode(hex);
        var portable=Assert.IsType<TrafficRecord>(IndustrialBatchWireFixtures.Capture(data,port,tcp,same));
        var h=new PacketHandler(()=>IndustrialBatchWireFixtures.Epoch);
        var r=Assert.IsType<TrafficRecord>(IndustrialBatchWireFixtures.Capture(data,port,tcp,same,
            parse:(bytes,link)=>h.ParseFrame(bytes,(LinkLayers)link)));
        Assert.Equal(op,portable.IndustrialOperation);
        Assert.Equal(op,r.IndustrialOperation);
        Assert.Equal(IndustrialBatchInspector.Label(op),r.ApplicationProtocol);
        Assert.Equal(portable.ApplicationProtocol,r.ApplicationProtocol);
        Assert.Equal((int?)data.Length,r.L4Len);
        Assert.True(RulePrecisionCatalog.HasField("capture_only_industrial_batch_operation",r));
        Assert.DoesNotContain("PRIVATE-COMMUNITY",JsonSerializer.Serialize(r));
        Assert.DoesNotContain("PRIVATE-BACNET-FILE",JsonSerializer.Serialize(r));
        r.Info="PRIVATE-INDUSTRIAL-FIXTURE-MARKER";
        var result=await rule.EvaluateAsync(At(r,0));
        Assert.True(result.Matched);
        Assert.False(result.Suppressed);
        Assert.Single(result.Events);
        var events=JsonSerializer.Serialize(result.Events);
        Assert.DoesNotContain("PRIVATE-INDUSTRIAL-FIXTURE-MARKER",events);
        Assert.DoesNotContain("PRIVATE-COMMUNITY",events);
        Assert.DoesNotContain("PRIVATE-BACNET-FILE",events);
        foreach(var other in AllRules().Where(x=>x.Descriptor.RuleId!=rule.Descriptor.RuleId))
            Assert.False((await other.EvaluateAsync(At(r,0))).Matched);
    }
    internal static async Task Negative(IDetectionRule rule,IndustrialBatchOperation op,int port,bool tcp,bool same,byte[] data,string variant="")
    {
        var r=IndustrialBatchWireFixtures.Capture(data,port,tcp,same,variant);
        if(r==null)return;
        if(variant!="private-source"&&variant!="public-destination")Assert.NotEqual(op,r.IndustrialOperation);
        Assert.False((await rule.EvaluateAsync(At(r,0))).Matched);
    }
    internal static async Task ProofAndState(Func<IDetectionRule> create,IndustrialBatchOperation op,int port,bool tcp,bool same,string hex)
    {
        var data=IndustrialBatchWireFixtures.Decode(hex);
        TrafficRecord Capture(string dst="10.1.2.45")=>Assert.IsType<TrafficRecord>(IndustrialBatchWireFixtures.Capture(data,port,tcp,same,dst:dst));
        var forged=JsonSerializer.Deserialize<TrafficRecord>("{\"IndustrialOperation\":"+(int)op+"}")!;
        Assert.Equal(IndustrialBatchOperation.None,forged.IndustrialOperation);
        var label=Capture();label.IndustrialOperation=IndustrialBatchOperation.None;
        Assert.False(RulePrecisionCatalog.HasField("capture_only_industrial_batch_operation",label));
        Assert.False((await create().EvaluateAsync(At(label,0))).Matched);
        foreach(string kind in new[]{"id","label","port","transport","dns","http","tls","quic","legacy"})
        {
            var r=Capture();
            switch(kind)
            {
                case "id":r.Id=Guid.Empty;break;
                case "label":r.ApplicationProtocol="invalid";break;
                case "port":r.DestinationPort=port+1;break;
                case "transport":r.IsTcp=r.IsUdp=true;break;
                case "dns":r.DnsIsResponse=true;break;
                case "http":r.HttpMethod="GET";break;
                case "tls":r.Sni="other.example";break;
                case "quic":r.IsQuic=true;break;
                case "legacy":r.BacnetWritePropertyRequestObserved=true;break;
            }
            Assert.False((await create().EvaluateAsync(At(r,0))).Matched);
        }
        var rule=create();var first=Capture();
        Assert.True((await rule.EvaluateAsync(At(first,100))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first,101))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Capture(),99))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),200))).Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Capture("10.1.2.46"),201))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Capture(),1000))).Matched);
        Assert.True((await create().EvaluateAsync(At(first,100))).Matched);
    }
}

public sealed class IndustrialBatchRegistryQualityTests
{
    [Fact]
    public void RegistryCoversFourDigitBoundaryAndProfiles()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        var ids=rules.Select(r=>r.Descriptor.RuleId).ToArray();
        Assert.True(ids.Length>=1000);
        Assert.Equal(ids.Length,ids.Distinct(StringComparer.OrdinalIgnoreCase).Count());
        Assert.Equal(Enumerable.Range(1,ids.Length).Select(n=>$"R{n:000}"),ids);
        Assert.Equal(ids,RuleCatalog.All.Select(d=>d.RuleId).ToArray());
        Assert.Equal(ids,RuleCatalog.AllAvailable.Where(d=>RuleIdValidator.IsCoreRuleId(d.RuleId)).Select(d=>d.RuleId).ToArray());
        Assert.True(RuleIdValidator.IsCoreRuleId("R999"));
        Assert.True(RuleIdValidator.IsCoreRuleId("R1000"));
        Assert.True(RuleIdValidator.IsCoreRuleId("R3085"));
        Assert.False(RuleIdValidator.IsPackRuleId("R1000"));
        Assert.False(RuleIdValidator.IsValid("R01000"));
        Assert.False(RuleIdValidator.IsValid("R000"));
        Assert.False(RuleIdValidator.IsValid("R99999999999999999999"));
        Assert.True(RuleIdValidator.IsPackRuleId("OT001"));
        Assert.Equal(410,RuleCatalog.AllAvailable.Count(d=>!RuleIdValidator.IsCoreRuleId(d.RuleId)));
        Assert.Empty(RuleCatalog.ValidateAvailable());
        Assert.Equal(ids,Carthago.Services.SessionFiles.CarthagoRuleCatalogExport.Build(Array.Empty<DetectionEvent>()).Select(r=>r.RuleId).ToArray());
        foreach(var expected in IndustrialBatchRuleAssertions.AllRules())
        {
            var rule=Assert.Single(rules.Where(x=>x.Descriptor.RuleId==expected.Descriptor.RuleId));
            Assert.Equal(expected.GetType(),rule.GetType());
            var profile=Assert.IsAssignableFrom<IndustrialBatchPrecisionRule>(rule).PrecisionProfile;
            Assert.Equal(RulePrecisionMaturity.Candidate,profile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow,profile.DefaultMode);
        }
    }
}
