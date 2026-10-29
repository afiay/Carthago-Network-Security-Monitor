// SPDX-License-Identifier: MIT
#if CARTHAGO_DNS_WIRE_STAGE4
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Parked private V2 replay-hydration contract. Every fixture is in-memory,
/// artificial and separate from the frozen V1 and pending external V2 corpus.
/// </summary>
public sealed class DnsWireReplayHydratorTests
{
    private const string EncodingVersion = "labels-base64-v1";

    [Fact]
    public void Hydrates_Explicit_V2_Wire_Labels()
    {
        string[] labels = { Encode(new byte[] { 0x00, 0x2e, 0x5c, 0x80, 0xff }),
            Encode("example"), Encode("test") };
        var sample = Sample();

        using var fixture = WireFixture(labels, EncodingVersion);
        DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample);

        var record = Assert.Single(sample.Records);
        Assert.Null(record.DnsQname);
        Assert.Equal(labels, record.DnsWireLabelsBase64);
        Assert.Equal("TXT", record.DnsQtype);
    }

    [Fact]
    public void Rejects_Conflicting_Legacy_And_Wire_Names()
    {
        var sample = Sample("safe.example");
        using var fixture = WireFixture(
            new[] { Encode("different"), Encode("example") }, EncodingVersion,
            legacyQname: "safe.example");

        Assert.Throws<InvalidDataException>(() =>
            DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample));
        Assert.Null(Assert.Single(sample.Records).DnsWireLabelsBase64);
    }

    [Fact]
    public void Accepts_Consistent_Ascii_Legacy_And_Wire_Names_With_Original_Bytes()
    {
        var sample = Sample("a.Example");
        string[] labels = { Encode("A"), Encode("EXAMPLE") };
        using var fixture = WireFixture(labels, EncodingVersion,
            legacyQname: "a.Example");

        DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample);

        Assert.Equal(labels, Assert.Single(sample.Records).DnsWireLabelsBase64);
        Assert.Equal("a.Example", Assert.Single(sample.Records).DnsQname);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("labels-base64-v0")]
    [InlineData("labels-base64-v2")]
    [InlineData("")]
    public void Rejects_Unversioned_Wire_Fields(string? version)
    {
        var sample = Sample();
        using var fixture = WireFixture(new[] { Encode("test"), Encode("example") },
            version);

        Assert.Throws<InvalidDataException>(() =>
            DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample));
        Assert.Null(Assert.Single(sample.Records).DnsWireLabelsBase64);
    }

    [Fact]
    public void Default_Replay_Json_Does_Not_Leak_Wire_Labels()
    {
        string[] labels = { Encode(new byte[] { 0x00, 0x80, 0xff }),
            Encode("example"), Encode("test") };
        var sample = Sample();
        using var fixture = WireFixture(labels, EncodingVersion);
        DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample);

        string generalJson = JsonSerializer.Serialize(sample);

        Assert.DoesNotContain("DnsWireLabelsBase64", generalJson, StringComparison.Ordinal);
        Assert.DoesNotContain("dnsWireLabelsBase64", generalJson, StringComparison.Ordinal);
        foreach (var label in labels)
            Assert.DoesNotContain(label, generalJson, StringComparison.Ordinal);
    }

    [Fact]
    public void Rejects_Invalid_Label_Atomically_Without_Partial_Hydration()
    {
        var sample = Sample();
        sample.Records.Add(new TrafficRecord
        {
            Source = "10.250.23.91",
            Destination = "8.8.8.8",
            DestinationPort = 53,
            DnsQtype = "TXT",
            IsUdp = true,
            Protocol = "DNS"
        });
        string json = JsonSerializer.Serialize(new
        {
            dnsWireNameEncoding = EncodingVersion,
            records = new object[]
            {
                new { dnsWireLabelsBase64 = new[] { Encode("first"), Encode("example") } },
                new { dnsWireLabelsBase64 = new[] { "AR==", Encode("example") } }
            }
        });
        using var fixture = JsonDocument.Parse(json);

        Assert.Throws<InvalidDataException>(() =>
            DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample));
        Assert.All(sample.Records, record => Assert.Null(record.DnsWireLabelsBase64));
    }

    [Fact]
    public void Rejects_Misaligned_Record_Count_Without_Changing_Sample()
    {
        var sample = Sample();
        string json = JsonSerializer.Serialize(new
        {
            dnsWireNameEncoding = EncodingVersion,
            records = new[]
            {
                new { dnsWireLabelsBase64 = new[] { Encode("first"), Encode("example") } },
                new { dnsWireLabelsBase64 = new[] { Encode("second"), Encode("example") } }
            }
        });
        using var fixture = JsonDocument.Parse(json);

        Assert.Throws<InvalidDataException>(() =>
            DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample));
        Assert.Null(Assert.Single(sample.Records).DnsWireLabelsBase64);
    }

    [Fact]
    public void Legacy_Sample_Without_Wire_Metadata_Is_Unchanged()
    {
        var sample = Sample("updates.example");
        using var fixture = JsonDocument.Parse(
            "{\"records\":[{\"dnsQname\":\"updates.example\"}]}");
        var originalRecord = Assert.Single(sample.Records);
        var originalId = originalRecord.Id;

        DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample);

        Assert.Same(originalRecord, Assert.Single(sample.Records));
        Assert.Equal(originalId, originalRecord.Id);
        Assert.Equal("updates.example", originalRecord.DnsQname);
        Assert.Null(originalRecord.DnsWireLabelsBase64);
    }

    [Fact]
    public void Rejects_Unexpected_Private_Wire_Fields()
    {
        var sample = Sample();
        string json = JsonSerializer.Serialize(new
        {
            dnsWireNameEncoding = EncodingVersion,
            records = new[]
            {
                new
                {
                    dnsWireLabelsBase64 = new[] { Encode("safe"), Encode("example") },
                    dnsWireLabelDebug = "reversible-and-unreviewed"
                }
            }
        });
        using var fixture = JsonDocument.Parse(json);

        Assert.Throws<InvalidDataException>(() =>
            DnsWireReplayHydrator.ApplyReviewedWireLabels(fixture.RootElement, sample));
        Assert.Null(Assert.Single(sample.Records).DnsWireLabelsBase64);
    }

    private static RuleReplaySample Sample(string? name = null) => new()
    {
        Name = "synthetic-private-wire-contract",
        Classification = ReplaySampleClassification.Malicious,
        Records = new List<TrafficRecord>
        {
            new()
            {
                Source = "10.250.23.90",
                Destination = "8.8.8.8",
                SourcePort = 53000,
                DestinationPort = 53,
                Protocol = "DNS",
                ApplicationProtocol = "DNS",
                IsUdp = true,
                DnsQname = name,
                DnsQtype = "TXT"
            }
        },
        ExpectedMatches = new List<string> { "R102" }
    };

    private static JsonDocument WireFixture(string[] labels, string? version,
        string? legacyQname = null)
    {
        var record = new Dictionary<string, object?>
        {
            ["dnsWireLabelsBase64"] = labels,
            ["dnsQname"] = legacyQname
        };
        var fields = new Dictionary<string, object?>
        {
            ["records"] = new[] { record }
        };
        if (version != null) fields["dnsWireNameEncoding"] = version;
        return JsonDocument.Parse(JsonSerializer.Serialize(fields));
    }

    private static string Encode(string text)
        => Encode(Encoding.ASCII.GetBytes(text));

    private static string Encode(byte[] bytes) => Convert.ToBase64String(bytes);
}
#endif // CARTHAGO_DNS_WIRE_STAGE4
