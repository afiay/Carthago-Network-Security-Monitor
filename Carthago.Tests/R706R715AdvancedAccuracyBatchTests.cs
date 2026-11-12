// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed.
using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R706R715AdvancedAccuracyBatchTests
{
    private static readonly DateTime Epoch = new(2026, 11, 4, 12, 0, 0, DateTimeKind.Utc);

    private static IDetectionRule Rule(string id) => id switch
    {
        "R706" => new R706_DirectHostPortKnockThenAdminSynRule(),
        "R707" => new R707_CompetingDhcpResponderDatagramsRule(),
        "R708" => new R708_PublicClientTftpExchangeToPrivateHostRule(),
        "R709" => new R709_PublicOversizedManagementHttpRequestRule(),
        "R710" => new R710_PublicMemcachedUdpFanoutRule(),
        "R711" => new R711_PlinkSshThenInternalAdminLegRule(),
        "R712" => new R712_SocatPublicIngressThenInternalAdminLegRule(),
        "R713" => new R713_NetcatExternalHighPortConnectPayloadRule(),
        "R714" => new R714_NetcatInternalMultiPortProbeRule(),
        "R715" => new R715_PrivateClientPublicTftpExchangeRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static RuleEvaluationContext At(TrafficRecord r, int seconds)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(seconds));

    private static TrafficRecord Syn(
        string source, string destination, int destinationPort,
        string? process = null, int pid = 0, int sourcePort = 53000)
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination, IpVersion = 4,
            Protocol = "TCP", IsTcp = true, IsUdp = false, SourcePort = sourcePort,
            DestinationPort = destinationPort, TcpFlags = 0x02, L4Len = 0, Length = 40,
            ProcessName = process, ProcessId = pid, Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Payload(
        string source, string destination, int destinationPort,
        string process, int pid, int sourcePort = 53000)
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination, IpVersion = 4,
            Protocol = "TCP", IsTcp = true, IsUdp = false, SourcePort = sourcePort,
            DestinationPort = destinationPort, TcpFlags = 0x18, L4Len = 180, Length = 220,
            ProcessName = process, ProcessId = pid, Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord Udp(
        string source, string destination, int sourcePort, int destinationPort, int l4 = 300)
        => new()
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination, IpVersion = 4,
            Protocol = "UDP", IsTcp = false, IsUdp = true, SourcePort = sourcePort,
            DestinationPort = destinationPort, L4Len = l4, Length = l4 + 28,
            Info = "RAW-SECRET-MARKER"
        };

    private static TrafficRecord OversizedHttp(int uriLength = 1300)
        => new()
        {
            Id = Guid.NewGuid(), Source = "8.8.8.8", Destination = "10.1.2.20", IpVersion = 4,
            Protocol = "TCP", IsTcp = true, SourcePort = 54000, DestinationPort = 8080,
            L4Len = 1600, Length = 1640, ApplicationProtocol = "HTTP",
            HttpMethod = "GET", HttpHost = "device.example",
            HttpUri = "/" + new string('a', Math.Max(2, uriLength - 24)) + "?token=VERY-PRIVATE",
            HttpUserAgent = "Browser/1.0", Info = "RAW-SECRET-MARKER"
        };

    private static async Task<RuleEvaluationResult> Trigger(IDetectionRule rule, string id, int start)
    {
        switch (id)
        {
            case "R706":
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41001),start));
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41002),start+1));
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41003),start+2));
                return await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",22),start+3));

            case "R707":
                await rule.EvaluateAsync(At(Udp("10.1.2.2","10.1.2.50",67,68),start));
                return await rule.EvaluateAsync(At(Udp("10.1.2.3","10.1.2.50",67,68),start+1));

            case "R708":
            {
                var pair = TftpCaptureQualificationTests.Exchange("8.8.8.8", "10.1.2.20", 2);
                await rule.EvaluateAsync(At(pair[0],start));
                return await rule.EvaluateAsync(At(pair[1],start+1));
            }

            case "R709":
                return await rule.EvaluateAsync(At(OversizedHttp(),start));

            case "R710":
                await rule.EvaluateAsync(At(Udp("10.1.2.20","8.8.8.8",54000,11211,40),start));
                await rule.EvaluateAsync(At(Udp("10.1.2.20","9.9.9.9",54000,11211,40),start+1));
                return await rule.EvaluateAsync(At(Udp("10.1.2.20","1.1.1.1",54000,11211,40),start+2));

            case "R711":
                await rule.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",22,"plink.exe",4100),start));
                return await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",3389,"plink.exe",4100),start+1));

            case "R712":
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",9000,"socat",4200),start));
                return await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",445,"socat",4200),start+1));

            case "R713":
                await rule.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",4444,"ncat",4300,53010),start));
                return await rule.EvaluateAsync(At(Payload("10.1.2.20","8.8.8.8",4444,"ncat",4300,53010),start+1));

            case "R714":
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",22,"nc",4400),start));
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",80,"nc",4400),start+1));
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",445,"nc",4400),start+2));
                return await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",3389,"nc",4400),start+3));

            case "R715":
            {
                var pair = TftpCaptureQualificationTests.Exchange("10.1.2.20", "8.8.8.8", 2);
                await rule.EvaluateAsync(At(pair[0],start));
                return await rule.EvaluateAsync(At(pair[1],start+1));
            }

            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> NearMiss(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R706":
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41001),0));
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41002),1));
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41002),2));
                return await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",22),3));
            case "R707":
                await rule.EvaluateAsync(At(Udp("10.1.2.2","10.1.2.50",67,68),0));
                return await rule.EvaluateAsync(At(Udp("10.1.2.2","10.1.2.50",67,68),1));
            case "R708":
                await rule.EvaluateAsync(At(Udp("8.8.8.8","10.1.2.20",53000,69,80),0));
                return await rule.EvaluateAsync(At(Udp("10.1.2.20","8.8.8.8",51000,53001,512),1));
            case "R709":
                return await rule.EvaluateAsync(At(OversizedHttp(300),0));
            case "R710":
                await rule.EvaluateAsync(At(Udp("10.1.2.20","8.8.8.8",54000,11211,40),0));
                await rule.EvaluateAsync(At(Udp("10.1.2.20","9.9.9.9",54000,11211,40),1));
                return await rule.EvaluateAsync(At(Udp("10.1.2.20","9.9.9.9",54000,11211,40),2));
            case "R711":
                await rule.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",22,"ssh.exe",4100),0));
                return await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",3389,"ssh.exe",4100),1));
            case "R712":
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",9000,"socat",4200),0));
                return await rule.EvaluateAsync(At(Syn("10.1.2.20","9.9.9.9",445,"socat",4200),1));
            case "R713":
                await rule.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",443,"ncat",4300,53010),0));
                return await rule.EvaluateAsync(At(Payload("10.1.2.20","8.8.8.8",443,"ncat",4300,53010),1));
            case "R714":
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",22,"nc",4400),0));
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",80,"nc",4400),1));
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",22,"nc",4400),2));
                return await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",80,"nc",4400),3));
            case "R715":
                await rule.EvaluateAsync(At(Udp("10.1.2.20","8.8.8.8",53000,69,80),0));
                return await rule.EvaluateAsync(At(Udp("8.8.8.8","10.1.2.20",51000,53001,512),1));
            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> MissingTelemetry(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R706":
            {
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41001),0));
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41002),1));
                await rule.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41003),2));
                var final=Syn("8.8.8.8","10.1.2.20",22); final.TcpFlags=null;
                return await rule.EvaluateAsync(At(final,3));
            }
            case "R707":
            {
                await rule.EvaluateAsync(At(Udp("10.1.2.2","10.1.2.50",67,68),0));
                var second=Udp("10.1.2.3","10.1.2.50",67,68); second.IpVersion=null;
                return await rule.EvaluateAsync(At(second,1));
            }
            case "R708":
            {
                await rule.EvaluateAsync(At(Udp("8.8.8.8","10.1.2.20",53000,69,80),0));
                var reply=Udp("10.1.2.20","8.8.8.8",51000,53000,512); reply.L4Len=null;
                return await rule.EvaluateAsync(At(reply,1));
            }
            case "R709":
            {
                var r=OversizedHttp(); r.ApplicationProtocol=null;
                return await rule.EvaluateAsync(At(r,0));
            }
            case "R710":
            {
                await rule.EvaluateAsync(At(Udp("10.1.2.20","8.8.8.8",54000,11211,40),0));
                await rule.EvaluateAsync(At(Udp("10.1.2.20","9.9.9.9",54000,11211,40),1));
                var third=Udp("10.1.2.20","1.1.1.1",54000,11211,40); third.DestinationPort=null;
                return await rule.EvaluateAsync(At(third,2));
            }
            case "R711":
            {
                await rule.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",22,"plink.exe",4100),0));
                var second=Syn("10.1.2.20","10.1.2.30",3389,"plink.exe",0);
                return await rule.EvaluateAsync(At(second,1));
            }
            case "R712":
            {
                var first=Syn("8.8.8.8","10.1.2.20",9000,null,4200);
                await rule.EvaluateAsync(At(first,0));
                return await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",445,"socat",4200),1));
            }
            case "R713":
            {
                await rule.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",4444,"ncat",4300,53010),0));
                var p=Payload("10.1.2.20","8.8.8.8",4444,"ncat",4300,53010); p.L4Len=null;
                return await rule.EvaluateAsync(At(p,1));
            }
            case "R714":
            {
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",22,"nc",4400),0));
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",80,"nc",4400),1));
                await rule.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",445,"nc",4400),2));
                var fourth=Syn("10.1.2.20","10.1.2.30",3389,"nc",0);
                return await rule.EvaluateAsync(At(fourth,3));
            }
            case "R715":
            {
                await rule.EvaluateAsync(At(Udp("10.1.2.20","8.8.8.8",53000,69,80),0));
                var reply=Udp("8.8.8.8","10.1.2.20",51000,53000,512); reply.Protocol=null;
                return await rule.EvaluateAsync(At(reply,1));
            }
            default:
                throw new ArgumentOutOfRangeException(nameof(id));
        }
    }

    private static async Task<RuleEvaluationResult> Contradictory(IDetectionRule rule, string id)
    {
        switch (id)
        {
            case "R709":
            {
                var r=OversizedHttp(); r.IsUdp=true;
                return await rule.EvaluateAsync(At(r,0));
            }
            case "R707":
            case "R708":
            case "R710":
            case "R715":
            {
                TrafficRecord r = id switch
                {
                    "R707" => Udp("10.1.2.2","10.1.2.50",67,68),
                    "R708" => Udp("8.8.8.8","10.1.2.20",53000,69,80),
                    "R710" => Udp("10.1.2.20","8.8.8.8",54000,11211,40),
                    _ => Udp("10.1.2.20","8.8.8.8",53000,69,80)
                };
                r.IsTcp=true;
                return await rule.EvaluateAsync(At(r,0));
            }
            default:
            {
                var r = id switch
                {
                    "R706" => Syn("8.8.8.8","10.1.2.20",41001),
                    "R711" => Syn("10.1.2.20","8.8.8.8",22,"plink.exe",4100),
                    "R712" => Syn("8.8.8.8","10.1.2.20",9000,"socat",4200),
                    "R713" => Syn("10.1.2.20","8.8.8.8",4444,"ncat",4300,53010),
                    "R714" => Syn("10.1.2.20","10.1.2.30",22,"nc",4400),
                    _ => throw new ArgumentOutOfRangeException(nameof(id))
                };
                r.IsUdp=true;
                return await rule.EvaluateAsync(At(r,0));
            }
        }
    }

    [Theory]
    [InlineData("R706")][InlineData("R707")][InlineData("R708")][InlineData("R709")][InlineData("R710")]
    [InlineData("R711")][InlineData("R712")][InlineData("R713")][InlineData("R714")][InlineData("R715")]
    public async Task PositiveShapeMatchesAndEvidenceIsRedacted(string id)
    {
        var result=await Trigger(Rule(id),id,0);
        Assert.True(result.Matched);
        var evt=Assert.Single(result.Events);
        var json=JsonSerializer.Serialize(evt);
        Assert.Contains("workbook.R",json);
        Assert.DoesNotContain("RAW-SECRET-MARKER",json);
        Assert.DoesNotContain("VERY-PRIVATE",json);
    }

    [Theory]
    [InlineData("R706")][InlineData("R707")][InlineData("R708")][InlineData("R709")][InlineData("R710")]
    [InlineData("R711")][InlineData("R712")][InlineData("R713")][InlineData("R714")][InlineData("R715")]
    public async Task BenignNearMissMissingTelemetryAndContradictoryFieldsDoNotMatch(string id)
    {
        Assert.False((await NearMiss(Rule(id),id)).Matched);
        Assert.False((await MissingTelemetry(Rule(id),id)).Matched);
        Assert.False((await Contradictory(Rule(id),id)).Matched);
    }

    [Fact]
    public async Task StatefulRulesRejectDuplicateIdsOutOfOrderTimestampsAndExpiredWindows()
    {
        // R706: duplicate one knock prevents exactly three distinct observations from completing.
        var r706=Rule("R706");
        var k1=Syn("8.8.8.8","10.1.2.20",41001);
        var k2=Syn("8.8.8.8","10.1.2.20",41002); k2.Id=k1.Id;
        await r706.EvaluateAsync(At(k1,0)); await r706.EvaluateAsync(At(k2,1));
        await r706.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41003),2));
        Assert.False((await r706.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",22),3))).Matched);
        var r706x=Rule("R706");
        await r706x.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41001),0));
        await r706x.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41002),1));
        await r706x.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",41003),2));
        Assert.False((await r706x.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",22),63))).Matched);

        // R707 distinct-responder correlation: duplicate and stale second observation cannot satisfy.
        var r707=Rule("R707"); var d1=Udp("10.1.2.2","10.1.2.50",67,68); var d2=Udp("10.1.2.3","10.1.2.50",67,68); d2.Id=d1.Id;
        await r707.EvaluateAsync(At(d1,0)); Assert.False((await r707.EvaluateAsync(At(d2,1))).Matched);
        var r707x=Rule("R707"); await r707x.EvaluateAsync(At(Udp("10.1.2.2","10.1.2.50",67,68),0));
        Assert.False((await r707x.EvaluateAsync(At(Udp("10.1.2.3","10.1.2.50",67,68),11))).Matched);

        // R708/R715 TFTP pair windows reject duplicate packet IDs, reverse time and expiry.
        foreach(var id in new[]{"R708","R715"})
        {
            var rule=Rule(id);
            var pair = id == "R708" ? TftpCaptureQualificationTests.Exchange("8.8.8.8","10.1.2.20",1)
                : TftpCaptureQualificationTests.Exchange("10.1.2.20","8.8.8.8",1);
            var req = pair[0]; var rep = pair[1];
            rep.Id=req.Id; await rule.EvaluateAsync(At(req,0)); Assert.False((await rule.EvaluateAsync(At(rep,1))).Matched);
            var late=Rule(id);
            pair = id == "R708" ? TftpCaptureQualificationTests.Exchange("8.8.8.8","10.1.2.20",1)
                : TftpCaptureQualificationTests.Exchange("10.1.2.20","8.8.8.8",1);
            await late.EvaluateAsync(At(pair[0],0)); Assert.False((await late.EvaluateAsync(At(pair[1],31))).Matched);
        }

        // R710 fanout, R711/R712 relay, R713 connect/payload and R714 multi-port windows all expire.
        var r710=Rule("R710");
        await r710.EvaluateAsync(At(Udp("10.1.2.20","8.8.8.8",54000,11211,40),0));
        await r710.EvaluateAsync(At(Udp("10.1.2.20","9.9.9.9",54000,11211,40),1));
        Assert.False((await r710.EvaluateAsync(At(Udp("10.1.2.20","1.1.1.1",54000,11211,40),62))).Matched);

        var r711=Rule("R711"); await r711.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",22,"plink.exe",4100),10));
        Assert.False((await r711.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",3389,"plink.exe",4100),9))).Matched);
        var r711x=Rule("R711"); await r711x.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",22,"plink.exe",4100),0));
        Assert.False((await r711x.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",3389,"plink.exe",4100),31))).Matched);

        var r712=Rule("R712"); await r712.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",9000,"socat",4200),0));
        Assert.False((await r712.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",445,"socat",4200),31))).Matched);

        var r713=Rule("R713"); await r713.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",4444,"ncat",4300,53010),0));
        Assert.False((await r713.EvaluateAsync(At(Payload("10.1.2.20","8.8.8.8",4444,"ncat",4300,53010),31))).Matched);

        var r714=Rule("R714");
        await r714.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",22,"nc",4400),0));
        await r714.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",80,"nc",4400),1));
        await r714.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",445,"nc",4400),2));
        Assert.False((await r714.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",3389,"nc",4400),33))).Matched);
    }

    [Fact]
    public async Task R709ReplayAndReverseTimeAreRejected()
    {
        var rule=Rule("R709");
        var record=OversizedHttp();
        Assert.True((await rule.EvaluateAsync(At(record,10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(record,11))).Matched);
        Assert.False((await rule.EvaluateAsync(At(OversizedHttp(),9))).Matched);
    }

    [Theory]
    [InlineData("R706")][InlineData("R707")][InlineData("R708")][InlineData("R709")][InlineData("R710")]
    [InlineData("R711")][InlineData("R712")][InlineData("R713")][InlineData("R714")][InlineData("R715")]
    public async Task EveryRuleHasIndependentCooldown(string id)
    {
        var rule=Rule(id);
        Assert.True((await Trigger(rule,id,0)).Matched);
        var second=await Trigger(rule,id,20);
        Assert.True(second.Suppressed);
        Assert.Empty(second.Events);
        Assert.True((await Trigger(rule,id,620)).Matched);
    }

    [Fact]
    public async Task NeighboringCandidatesRemainNonConverged()
    {
        // Inbound TFTP belongs to R708, not outbound R715.
        var inbound715=Rule("R715");
        await inbound715.EvaluateAsync(At(Udp("8.8.8.8","10.1.2.20",53000,69,80),0));
        Assert.False((await inbound715.EvaluateAsync(At(Udp("10.1.2.20","8.8.8.8",51000,53000,512),1))).Matched);

        // Plink and Socat identities are not interchangeable.
        var plinkAsSocat=Rule("R712");
        await plinkAsSocat.EvaluateAsync(At(Syn("8.8.8.8","10.1.2.20",9000,"plink.exe",4100),0));
        Assert.False((await plinkAsSocat.EvaluateAsync(At(Syn("10.1.2.20","10.1.2.30",445,"plink.exe",4100),1))).Matched);

        // Netcat external-connect shape does not satisfy the internal multi-port rule.
        var internalRule=Rule("R714");
        await internalRule.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",4444,"ncat",4300,53010),0));
        Assert.False((await internalRule.EvaluateAsync(At(Syn("10.1.2.20","8.8.8.8",5555,"ncat",4300,53010),1))).Matched);
    }

    [Theory]
    [InlineData("R706")][InlineData("R707")][InlineData("R708")][InlineData("R709")][InlineData("R710")]
    [InlineData("R711")][InlineData("R712")][InlineData("R713")][InlineData("R714")][InlineData("R715")]
    public void RegistryContainsExactlyOneCandidateShadow(string id)
    {
        var found=Assert.Single(RuleRegistry.CreateDefaultRules().Where(x=>x.Descriptor.RuleId==id));
        var precision=Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(found);
        Assert.Equal(RulePrecisionMaturity.Candidate,precision.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow,precision.PrecisionProfile.DefaultMode);
    }

    [Fact]
    public void RegistryHasNoDuplicateRuleIds()
    {
        var rules=RuleRegistry.CreateDefaultRules();
        Assert.Equal(rules.Count, rules.Select(x=>x.Descriptor.RuleId).Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }
}
