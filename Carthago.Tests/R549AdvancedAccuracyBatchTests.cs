// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using SharpPcap;
using Xunit;

namespace Carthago.Tests;

public sealed class R549AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 2, 0, 0, 0, DateTimeKind.Utc);
    private const string DefaultBasic = "YWRtaW46YWRtaW4="; // Non-secret synthetic admin:admin fixture.

    private static TrafficRecord Sample(string source = "10.1.1.10",
        string destination = "10.2.1.20", string path = "/admin",
        string credential = DefaultBasic, string extraHeaders = "")
    {
        var request = "GET " + path + " HTTP/1.1\r\nHost: camera.lab.internal\r\n"
            + "Authorization: Basic " + credential + "\r\n" + extraHeaders + "\r\n";
        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(request), out var parsed));
        return new TrafficRecord
        {
            Id = Guid.NewGuid(), Source = source, Destination = destination,
            Protocol = "TCP", ApplicationProtocol = "HTTP", IsTcp = true, IsUdp = false,
            IpVersion = 4, SourcePort = 51000, DestinationPort = 80,
            L4Len = Encoding.ASCII.GetByteCount(request), Length = 200,
            HttpMethod = parsed.Method, HttpUri = parsed.Path, HttpHost = parsed.Host,
            HttpRequestHeaders = parsed.JoinedHeaderLines,
            HttpBasicDefaultCredentialObserved = parsed.ObservedDefaultBasicCredential,
            Info = "synthetic diagnostic only"
        };
    }

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    private static async Task<RuleEvaluationResult> Three(
        R549_CrossSubnetDefaultBasicCredentialFanoutRule rule,
        TrafficRecord first, TrafficRecord second, TrafficRecord third)
    {
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(second, 1))).Matched);
        return await rule.EvaluateAsync(At(third, 2));
    }

    [Fact]
    public void Bounded_Http_Parser_Recognizes_Complete_Default_Basic_And_Redacts_Bytes()
    {
        var record = Sample();
        Assert.True(record.HttpBasicDefaultCredentialObserved);
        Assert.Contains("Authorization: [REDACTED]", record.HttpRequestHeaders);
        Assert.DoesNotContain(DefaultBasic, record.HttpRequestHeaders);
    }

    [Fact]
    public void PacketHandler_Produces_Default_Basic_Flag_From_Raw_Ipv4_Tcp_Request()
    {
        var payload = Encoding.ASCII.GetBytes(
            "GET /admin HTTP/1.1\r\nHost: camera.lab.internal\r\nAuthorization: Basic "
            + DefaultBasic + "\r\n\r\n");
        var frame = new byte[40 + payload.Length];
        frame[0] = 0x45;
        frame[2] = (byte)(frame.Length >> 8); frame[3] = (byte)frame.Length;
        frame[8] = 64; frame[9] = 6;
        IPAddress.Parse("10.1.1.10").GetAddressBytes().CopyTo(frame, 12);
        IPAddress.Parse("10.2.1.20").GetAddressBytes().CopyTo(frame, 16);
        frame[20] = 0xc7; frame[21] = 0x38; // TCP source port 51000
        frame[23] = 80; frame[32] = 0x50; frame[33] = 0x18;
        payload.CopyTo(frame, 40);
        var record = new PacketHandler().ParseFrame(frame, (LinkLayers)12);
        Assert.NotNull(record);
        Assert.True(record.HttpBasicDefaultCredentialObserved);
        Assert.Equal("HTTP", record.ApplicationProtocol);
        Assert.DoesNotContain(DefaultBasic, record.HttpRequestHeaders);
    }

    [Fact]
    public async Task Three_Distinct_Private_Subnets_Produce_High_Severity_Candidate()
    {
        var result = await Three(new R549_CrossSubnetDefaultBasicCredentialFanoutRule(),
            Sample(destination: "10.2.1.20"), Sample(destination: "10.3.1.20"),
            Sample(destination: "10.4.1.20"));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R549", evt.RuleId);
        Assert.Equal(SeverityLevel.High, evt.Severity);
        Assert.Equal(3, evt.Count);
        Assert.Equal(300, evt.WindowSeconds);
    }

    [Theory]
    [InlineData("YWRtaW46c3Ryb25nLXBhc3M=")]
    [InlineData("not-base64")]
    public async Task Unknown_Or_Malformed_Basic_Credential_Does_Not_Qualify(string credential)
    {
        Assert.False((await Three(new R549_CrossSubnetDefaultBasicCredentialFanoutRule(),
            Sample(destination: "10.2.1.20", credential: credential),
            Sample(destination: "10.3.1.20", credential: credential),
            Sample(destination: "10.4.1.20", credential: credential))).Matched);
    }

    [Fact]
    public async Task Duplicate_Authorization_And_Incomplete_Header_Fail_Closed()
    {
        var duplicate = Sample(extraHeaders: "Authorization: Bearer synthetic\r\n");
        Assert.False(duplicate.HttpBasicDefaultCredentialObserved);
        var incomplete = "GET /admin HTTP/1.1\r\nHost: camera.lab.internal\r\n"
            + "Authorization: Basic " + DefaultBasic + "\r\n";
        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(incomplete), out var parsed));
        Assert.False(parsed.ObservedDefaultBasicCredential);
        Assert.False((await new R549_CrossSubnetDefaultBasicCredentialFanoutRule()
            .EvaluateAsync(At(duplicate))).Matched);
    }

    [Theory]
    [InlineData("/docs")]
    [InlineData("/index.html")]
    [InlineData("/assets/admin.js")]
    public async Task NonAdmin_Paths_Are_Benign_Negatives(string path)
    {
        Assert.False((await Three(new R549_CrossSubnetDefaultBasicCredentialFanoutRule(),
            Sample(destination: "10.2.1.20", path: path),
            Sample(destination: "10.3.1.20", path: path),
            Sample(destination: "10.4.1.20", path: path))).Matched);
    }

    [Fact]
    public async Task One_Subnet_Or_Source_Local_Subnet_Does_Not_Count_As_Fanout()
    {
        Assert.False((await Three(new R549_CrossSubnetDefaultBasicCredentialFanoutRule(),
            Sample(destination: "10.2.1.20"), Sample(destination: "10.2.1.21"),
            Sample(destination: "10.2.1.22"))).Matched);
        Assert.False((await Three(new R549_CrossSubnetDefaultBasicCredentialFanoutRule(),
            Sample(destination: "10.1.1.20"), Sample(destination: "10.2.1.20"),
            Sample(destination: "10.3.1.20"))).Matched);
    }

    [Theory]
    [InlineData("8.8.8.8", "10.2.1.20")]
    [InlineData("10.1.1.10", "8.8.8.8")]
    [InlineData("192.0.2.10", "10.2.1.20")]
    [InlineData("10.1.1.10", "169.254.2.20")]
    public async Task Public_Or_NonRfc1918_Endpoints_Are_Rejected(string source, string destination)
    {
        Assert.False((await new R549_CrossSubnetDefaultBasicCredentialFanoutRule()
            .EvaluateAsync(At(Sample(source, destination)))).Matched);
    }

    [Fact]
    public async Task PortOnly_And_Freeform_Info_Cannot_Forge_Default_Credential()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        var record = Sample(credential: "YWRtaW46c3Ryb25nLXBhc3M=");
        record.Info = "Authorization: Basic " + DefaultBasic;
        record.HttpRequestHeaders = "Authorization: [REDACTED]";
        Assert.False((await rule.EvaluateAsync(At(record))).Matched);
    }

    [Fact]
    public async Task Imported_Json_Cannot_Set_Parser_Only_Default_Credential_Bit()
    {
        var imported = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"HttpBasicDefaultCredentialObserved\":true,\"Source\":\"10.1.1.10\"}");
        Assert.NotNull(imported);
        Assert.False(imported.HttpBasicDefaultCredentialObserved);
        Assert.False((await new R549_CrossSubnetDefaultBasicCredentialFanoutRule()
            .EvaluateAsync(At(imported))).Matched);
    }

    [Fact]
    public async Task Contradictory_Transport_And_Encrypted_Evidence_Fails_Closed()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        var tls = Sample(); tls.TlsVersion = "TLS1.3";
        var quic = Sample(); quic.IsQuic = true;
        var dns = Sample(); dns.DnsQname = "internal.example";
        var udp = Sample(); udp.IsTcp = false; udp.IsUdp = true; udp.Protocol = "UDP";
        Assert.False((await rule.EvaluateAsync(At(tls))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quic, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(udp, 3))).Matched);
    }

    [Fact]
    public async Task Invalid_Ports_Payload_And_Host_Fail_Closed()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        var port = Sample(); port.DestinationPort = 443;
        var sourcePort = Sample(); sourcePort.SourcePort = 80;
        var length = Sample(); length.L4Len = 4097;
        var host = Sample(); host.HttpHost = "secret@camera.lab.internal";
        Assert.False((await rule.EvaluateAsync(At(port))).Matched);
        Assert.False((await rule.EvaluateAsync(At(sourcePort, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(length, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(host, 3))).Matched);
    }

    [Fact]
    public async Task Duplicate_Packet_Id_Cannot_Complete_Fanout()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        var first = Sample(destination: "10.2.1.20");
        var duplicate = Sample(destination: "10.3.1.20"); duplicate.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(duplicate, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.4.1.20"), 2))).Matched);
    }

    [Fact]
    public async Task Out_Of_Order_Timestamps_Cannot_Complete_Threshold()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.2.1.20"), 30))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.3.1.20"), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.4.1.20"), 31))).Matched);
    }

    [Fact]
    public async Task Different_Sources_Cannot_Accumulate_Each_Others_Targets()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.2.1.20"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(source: "10.1.1.11", destination: "10.3.1.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.4.1.20"), 2))).Matched);
    }

    [Fact]
    public async Task Expired_Window_Does_Not_Reuse_Old_Subnets()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.2.1.20"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.3.1.20"), 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.4.1.20"), 302))).Matched);
    }

    [Fact]
    public async Task Cooldown_Records_Suppression_Without_Second_Event()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        Assert.True((await Three(rule, Sample(destination: "10.2.1.20"),
            Sample(destination: "10.3.1.20"), Sample(destination: "10.4.1.20"))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.2.1.20"), 303))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(destination: "10.3.1.20"), 304))).Matched);
        var result = await rule.EvaluateAsync(At(Sample(destination: "10.4.1.20"), 305));
        Assert.True(result.Suppressed);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task Concurrent_Observations_Emit_At_Most_One_Candidate()
    {
        var rule = new R549_CrossSubnetDefaultBasicCredentialFanoutRule();
        var tasks = new[]
        {
            rule.EvaluateAsync(At(Sample(destination: "10.2.1.20"))).AsTask(),
            rule.EvaluateAsync(At(Sample(destination: "10.3.1.20"))).AsTask(),
            rule.EvaluateAsync(At(Sample(destination: "10.4.1.20"))).AsTask()
        };
        var results = await Task.WhenAll(tasks);
        Assert.Equal(1, results.Count(result => result.Matched));
    }

    [Fact]
    public async Task Evidence_Does_Not_Retain_Credential_Header_Or_Untrusted_Info()
    {
        var a = Sample(destination: "10.2.1.20");
        var b = Sample(destination: "10.3.1.20");
        var c = Sample(destination: "10.4.1.20");
        c.Info = "secret marker " + DefaultBasic;
        var result = await Three(new R549_CrossSubnetDefaultBasicCredentialFanoutRule(), a, b, c);
        var json = JsonSerializer.Serialize(Assert.Single(result.Events));
        Assert.DoesNotContain(DefaultBasic, json);
        Assert.DoesNotContain("secret marker", json);
        Assert.DoesNotContain("Authorization:", json, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("http.defaultBasicObserved", json);
    }

    [Fact]
    public void Registry_And_Policy_Preserve_Unique_Id_Shadow_And_Confidence()
    {
        var registered = RuleRegistry.CreateDefaultRules()
            .Where(rule => rule.Descriptor.RuleId == "R549").ToArray();
        var rule = Assert.IsType<R549_CrossSubnetDefaultBasicCredentialFanoutRule>(Assert.Single(registered));
        Assert.Equal("Rules.R549.Enabled", rule.Descriptor.ConfigKey);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(88, rule.PrecisionProfile.MinimumConfidence);
    }
}
