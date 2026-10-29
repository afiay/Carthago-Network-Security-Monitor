// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Models;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Development fixtures only. Frozen v1/v2 holdout inputs never feed these
/// test expectations, and no Windows packet capture or network is required.
/// </summary>
public sealed class DnsReplayTelemetryDiagnosticsTests
{
    private static readonly string LongLabel =
        "zx9q8v7m6n5p4t3k2rz0h1w2c3v4b5n6m7l8k9j0i1u2y3t4r5s6";

    private static TrafficRecord Dns(bool udp = true) => new()
    {
        Source = "10.111.2.3",
        Destination = "8.8.8.8",
        SourcePort = 51000,
        DestinationPort = 53,
        IpVersion = 4,
        Protocol = "DNS",
        ApplicationProtocol = "DNS",
        DnsQtype = "TXT",
        DnsQname = LongLabel + ".offline-validation.example",
        IsUdp = udp
    };

    [Fact]
    public void Missing_Transport_Is_Reported_But_Never_Inferred_Or_Persisted()
    {
        var record = Dns(udp: false);
        var originalId = record.Id;
        var originalName = record.DnsQname;
        var codes = DnsReplayTelemetryDiagnostics.Inspect(record);
        Assert.Equal(new[] { "DNS_TRANSPORT_UNATTRIBUTED" }, codes);
        Assert.False(record.IsUdp);
        Assert.False(record.IsTcp);
        Assert.Equal(originalId, record.Id);
        Assert.Equal(originalName, record.DnsQname);
        Assert.DoesNotContain("10.111.2.3", string.Join(",", codes));
        Assert.DoesNotContain(LongLabel, string.Join(",", codes));
    }

    [Fact]
    public void Explicit_Coherent_Udp_Query_Has_No_Missing_Telemetry()
    {
        Assert.Empty(DnsReplayTelemetryDiagnostics.Inspect(Dns()));
    }

    [Fact]
    public void Contradictory_Transport_Bits_Are_Not_Treated_As_Udp()
    {
        var record = Dns();
        record.IsTcp = true;
        Assert.Contains("DNS_TRANSPORT_CONFLICT",
            DnsReplayTelemetryDiagnostics.Inspect(record));
    }

    [Fact]
    public void Tcp_Syn_Without_Payload_Is_Not_An_Attributed_Dns_Question()
    {
        var record = Dns(udp: false);
        record.IsTcp = true;
        record.TcpFlags = 0x02;
        Assert.Contains("DNS_TCP_NOT_DATA",
            DnsReplayTelemetryDiagnostics.Inspect(record));
    }

    [Fact]
    public void Missing_Question_And_Type_Have_Distinct_Payload_Free_Codes()
    {
        var record = Dns();
        record.DnsQname = null;
        record.DnsQtype = null;
        var codes = DnsReplayTelemetryDiagnostics.Inspect(record);
        Assert.Contains("DNS_QNAME_MISSING", codes);
        Assert.Contains("DNS_QTYPE_MISSING", codes);
    }

    [Fact]
    public void Dns_Http_Field_Conflict_Is_Diagnostic_Only()
    {
        var record = Dns();
        record.HttpMethod = "GET";
        Assert.Contains("DNS_HTTP_FIELDS_CONFLICT",
            DnsReplayTelemetryDiagnostics.Inspect(record));
        Assert.Equal("GET", record.HttpMethod);
    }

    [Fact]
    public async Task Benchmark_Reports_Missing_Transport_Without_Creating_R102_Match()
    {
        var dir = Path.Combine(Path.GetTempPath(),
            "carthago-dns-diagnostic-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try
        {
            // Deliberately omit UDP/TCP. Use an entirely new synthetic
            // scenario: it is not a copy of either frozen holdout case.
            var sample = new
            {
                name = "development-dns-transport-unknown",
                classification = "Malicious",
                records = new[] { new {
                    source = "10.111.2.3", destination = "8.8.8.8",
                    protocol = "DNS", applicationProtocol = "DNS",
                    destinationPort = 53, dnsQname = LongLabel + ".offline-validation.example",
                    dnsQtype = "TXT"
                }},
                expectedMatches = new[] { "R102" },
                expectedNonMatches = new[] { "R118", "R163" },
                expectedMinimumConfidence = 0.75
            };
            await File.WriteAllTextAsync(Path.Combine(dir, "sample.json"),
                JsonSerializer.Serialize(sample));

            var report = await new TuningBenchmarkRunner().RunAsync(
                new TuningBenchmarkOptions { ReplayDirectory = dir });
            var result = Assert.Single(report.SampleResults);
            Assert.DoesNotContain("R102", result.ActualMatches);
            var diagnostic = Assert.Single(result.ExpectedRuleDiagnostics);
            Assert.Equal("R102", diagnostic.RuleId);
            Assert.Equal("InvalidInputTelemetry", diagnostic.Outcome);
            Assert.Equal(1, diagnostic.InputRecordsInspected);
            Assert.Equal(1, diagnostic.InputRecordsWithIssues);
            Assert.Equal(new[] { "DNS_TRANSPORT_UNATTRIBUTED" },
                diagnostic.InputTelemetryIssueCodes);

            var gaps = report.RecallGaps.Where(gap => gap.RuleId == "R102").ToArray();
            Assert.NotEmpty(gaps);
            Assert.All(gaps, gap =>
            {
                Assert.Equal("InvalidInputTelemetry", gap.Cause);
                Assert.Contains("Input telemetry: DNS_TRANSPORT_UNATTRIBUTED",
                    gap.Evidence);
                Assert.DoesNotContain("10.111.2.3", string.Join(",", gap.Evidence));
            });
        }
        finally
        {
            if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true);
        }
    }
}
