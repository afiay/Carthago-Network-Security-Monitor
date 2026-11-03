// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; TESTS AUTHORED; 0 EXECUTED.
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

public sealed class R585AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 3, 0, 0, 0, DateTimeKind.Utc);
    private static R585_ExternalThreeServiceAdministrativeProbeRule NewRule() => new();
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static TrafficRecord Sample(int service, string client = "8.8.8.8",
        string server = "10.4.1.10")
    {
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), Source = client, Destination = server,
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 51001, DestinationPort = 80, L4Len = 120, Length = 200,
            ApplicationProtocol = "HTTP", HttpBasicDefaultCredentialObserved = true,
            HttpMethod = "GET", HttpUri = "/admin", HttpHost = "gateway.lab.internal",
            HttpRequestHeaders = "Authorization: [REDACTED]"
        };
        if (service == 2)
        {
            r.DestinationPort = 6379; r.L4Len = 64;
            r.ApplicationProtocol = "redis.resp2";
            r.HttpBasicDefaultCredentialObserved = false;
            r.HttpMethod = null; r.HttpUri = null; r.HttpHost = null;
            r.HttpRequestHeaders = null; r.RedisRespConfigSetRequestObserved = true;
        }
        else if (service == 4)
        {
            r.DestinationPort = 445; r.L4Len = 117;
            r.ApplicationProtocol = "smb2.write.request";
            r.HttpBasicDefaultCredentialObserved = false;
            r.HttpMethod = null; r.HttpUri = null; r.HttpHost = null;
            r.HttpRequestHeaders = null;
        }
        return r;
    }

    [Theory]
    [InlineData(1, 2, 4)]
    [InlineData(4, 2, 1)]
    [InlineData(2, 1, 4)]
    public async Task ThreeIndependentClassifiedServicesMatchInAnyOrder(int first, int second, int third)
    {
        var rule = NewRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(first)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(second), 1))).Matched);
        var result = await rule.EvaluateAsync(At(Sample(third), 2));
        Assert.True(result.Matched);
        Assert.Equal("R585", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task TwoServicesNeverSufficeEvenWithRepeatedRequests()
    {
        var rule = NewRule();
        for (var i = 0; i < 6; i++)
            Assert.False((await rule.EvaluateAsync(At(Sample(i % 2 == 0 ? 1 : 2), i))).Matched);
    }

    [Fact] public async Task DifferentPublicClientsCannotCombine()
    {
        var rule = NewRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(1)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(2), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(4, client: "9.9.9.9"), 2))).Matched);
    }

    [Fact] public async Task DifferentPrivateHostsCannotCombine()
    {
        var rule = NewRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(1)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(2), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(4, server: "10.4.1.11"), 2))).Matched);
    }

    [Fact] public async Task DuplicatePacketIdentifiersDoNotSatisfyThreeServices()
    {
        var rule = NewRule();
        var a = Sample(1); var b = Sample(2); b.Id = a.Id;
        Assert.False((await rule.EvaluateAsync(At(a))).Matched);
        Assert.False((await rule.EvaluateAsync(At(b, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(4), 2))).Matched);
    }

    [Fact] public async Task OutOfOrderAndEqualTimestampsCannotCompleteTriad()
    {
        var rule = NewRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(1), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(2), 9))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(4), 10))).Matched);
    }

    [Fact] public async Task ExpiredFirstServiceCannotCompleteTriad()
    {
        var rule = NewRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(1)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(2), 301))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(4), 302))).Matched);
    }

    [Fact] public async Task PortOnlyInfoOnlyAndOrdinaryOperationsCannotSeed()
    {
        var rule = NewRule();
        var redis = Sample(2); redis.RedisRespConfigSetRequestObserved = false;
        redis.Info = "CONFIG SET";
        var http = Sample(1); http.HttpBasicDefaultCredentialObserved = false;
        var smb = Sample(4); smb.ApplicationProtocol = "smb2.create.request";
        Assert.False((await rule.EvaluateAsync(At(redis))).Matched);
        Assert.False((await rule.EvaluateAsync(At(http, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(smb, 2))).Matched);
    }

    [Fact] public async Task ContradictoryAndReservedMetadataRejected()
    {
        var rule = NewRule();
        var tls = Sample(1); tls.TlsVersion = "TLS1.3";
        var dns = Sample(2); dns.DnsQname = "forged.invalid";
        var quic = Sample(4); quic.IsQuic = true;
        var reserved = Sample(1, client: "192.0.2.10");
        Assert.False((await rule.EvaluateAsync(At(tls))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quic, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(reserved, 3))).Matched);
    }

    [Fact] public async Task RepeatedTriadDuringCooldownDoesNotCreateAnotherEvent()
    {
        var rule = NewRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(1)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(2), 1))).Matched);
        Assert.Single((await rule.EvaluateAsync(At(Sample(4), 2))).Events);
        Assert.False((await rule.EvaluateAsync(At(Sample(1), 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(2), 4))).Matched);
        Assert.Empty((await rule.EvaluateAsync(At(Sample(4), 5))).Events);
    }

    [Fact] public async Task EvidenceContainsNoCredentialsOrRawPayload()
    {
        var rule = NewRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(1)))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(2), 1))).Matched);
        var result = await rule.EvaluateAsync(At(Sample(4), 2));
        var serialized = JsonSerializer.Serialize(Assert.Single(result.Events));
        Assert.DoesNotContain("Authorization:", serialized);
        Assert.DoesNotContain("CONFIG SET", serialized);
        Assert.DoesNotContain("gateway.lab.internal", serialized);
        Assert.Contains("requests_only_unknown", serialized);
    }

    [Fact] public void CandidateShadowAndRegistryUniqueness()
    {
        var rule = Assert.IsType<R585_ExternalThreeServiceAdministrativeProbeRule>(
            Assert.Single(RuleRegistry.CreateDefaultRules().Where(r => r.Descriptor.RuleId == "R585")));
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(90, rule.PrecisionProfile.MinimumConfidence);
    }
}
