// SPDX-License-Identifier: MIT
using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Dns;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.Benchmarking;
using Carthago.Services.EnvironmentTuning;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Synthetic, intentionally unexecuted RED contracts for R102 binary DNS
/// evidence. No external capture, frozen holdout or private QNAME is embedded.
/// The owner must explicitly authorize focused Windows tests.
/// </summary>
[Collection("R102 distinct TXT correlation")]
public sealed class R102BinaryDnsPrecisionTests
{
    private static readonly DateTime BaseTime =
        new(2026, 10, 29, 9, 0, 0, DateTimeKind.Utc);

    private static readonly string[] HighEntropyLabels =
    {
        "x9q8v7m6n5p4t3k2rz0h1w2c3v4b5n6m7l8k9j0i1u2y3t4r5s6",
        "v6n1z7m3q9w4t0p5k8c2r6b1s7x3j9d4h0f5l8y2g6a1e7o3u9",
        "q4n8v2x6k0s5p9h3t7w1r4m8y2c6j0d5f9g3b7l1z4a8e2u6i0"
    };

    [Fact]
    public async Task R102_Detects_Three_Distinct_Binary_Txt_Names_Without_Lowering_Floor()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var source = "10.250.23.77";
        var root = NewRoot("binary");
        DetectionEvent? first = null;
        DetectionEvent? third = null;

        for (var index = 0; index < 3; index++)
        {
            var record = WireRecord(source, root, BinaryLabel(index));
            var result = await rule.EvaluateAsync(new RuleEvaluationContext(
                record, Sensitivity.Balanced, BaseTime.AddSeconds(index * 20)));
            Assert.True(result.Matched);
            var evt = Assert.Single(result.Events);
            Assert.Equal((index + 1).ToString(CultureInfo.InvariantCulture),
                EvidenceValue(evt, "dns.distinctSuspiciousTxtNames"));
            Assert.Equal(index == 2, EvidenceValue(evt, "matched_conditions")
                .Contains("multiple_distinct_suspicious_txt_names",
                    StringComparison.OrdinalIgnoreCase));
            first ??= evt;
            third = evt;
        }

        Assert.NotNull(first);
        Assert.NotNull(third);
        Assert.True(third!.ConfidenceScore > first!.ConfidenceScore);
        Assert.True(third.ConfidenceScore >= 0.80);
        Assert.Equal(80, rule.PrecisionProfile.MinimumConfidence);

        // A detected wire-valid query is not automatically promoted to an
        // alert in a profile with no independently ready baseline.
        var tuning = RuleTuningCatalog.Resolve("SmallBusiness",
            rule.Descriptor, third, WireRecord(source, root, BinaryLabel(2)),
            new ApprovedAssetRegistry(new EnvironmentTuningOptions()),
            baselineReady: false);
        Assert.Equal(RuleMode.Shadow, tuning.EffectiveMode);
    }

    [Fact]
    public async Task R102_Binary_Evidence_Contains_No_Raw_Qname()
    {
        var source = "10.250.23.78";
        var root = NewRoot("privacy");
        var record = WireRecord(source, root, BinaryLabel(0));
        var result = await new R102_DNSTunnelingViaLongLabelsRule()
            .EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, BaseTime));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        var serialized = JsonSerializer.Serialize(evt);

        Assert.NotNull(evt.StructuredEvidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => string.Equals(item.Key, "dns.qname", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(evt.StructuredEvidence.Items,
            item => string.Equals(item.Key, "dns.maxLabelLength", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(evt.StructuredEvidence.Items,
            item => string.Equals(item.Key, "dns.longestLabelEntropy", StringComparison.OrdinalIgnoreCase));

        // Reversible Base64, source identity, and replacement-character text
        // must not enter ordinary binary-name alert serialization.
        foreach (var label in record.DnsWireLabelsBase64!)
            Assert.DoesNotContain(label, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain(source, serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("\uFFFD", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain(@"\uFFFD", serialized, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("?", evt.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task R102_Mirrored_Retries_Do_Not_Add_Distinct_Confidence()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var root = NewRoot("mirror");
        var firstLabel = BinaryLabel(0);
        var original = WireRecord("10.250.23.79", root, firstLabel);
        var first = await rule.EvaluateAsync(new RuleEvaluationContext(
            original, Sensitivity.Balanced, BaseTime));
        Assert.True(first.Matched);
        Assert.Equal("1", EvidenceValue(Assert.Single(first.Events),
            "dns.distinctSuspiciousTxtNames"));

        // Identical packet ID and name: dedup, not a new observation.
        var replay = await rule.EvaluateAsync(new RuleEvaluationContext(
            original, Sensitivity.Balanced, BaseTime.AddSeconds(10)));
        Assert.False(replay.Matched);
        Assert.Empty(replay.Events);

        // New packet, same DNS name: still one distinct name.
        var repeat = await rule.EvaluateAsync(new RuleEvaluationContext(
            WireRecord(original.Source!, root, firstLabel),
            Sensitivity.Balanced, BaseTime.AddSeconds(20)));
        Assert.True(repeat.Matched);
        Assert.Equal("1", EvidenceValue(Assert.Single(repeat.Events),
            "dns.distinctSuspiciousTxtNames"));

        // Another observed source IP with a mirrored name must not amplify
        // the first source's root-scoped distinct-name confidence.
        var mirrored = await rule.EvaluateAsync(new RuleEvaluationContext(
            WireRecord("10.250.23.80", root, firstLabel),
            Sensitivity.Balanced, BaseTime.AddSeconds(30)));
        Assert.True(mirrored.Matched);
        Assert.Equal("1", EvidenceValue(Assert.Single(mirrored.Events),
            "dns.distinctSuspiciousTxtNames"));
    }

    [Fact]
    public async Task R102_Ascii_Case_Retries_Do_Not_Inflate_Binary_Distinct_Names()
    {
        var rule = new R102_DNSTunnelingViaLongLabelsRule();
        var root = NewRoot("casefold");
        var first = BinaryLabel(0);
        var second = (byte[])first.Clone();
        for (int index = 0; index < second.Length; index++)
        {
            if (second[index] >= (byte)'a' && second[index] <= (byte)'z')
                second[index] -= 32;
        }
        var source = "10.250.23.81";

        for (var index = 0; index < 2; index++)
        {
            var bytes = index == 0 ? first : second;
            var result = await rule.EvaluateAsync(new RuleEvaluationContext(
                WireRecord(source, root, bytes), Sensitivity.Balanced,
                BaseTime.AddSeconds(index * 20)));
            Assert.True(result.Matched);
            Assert.Equal("1", EvidenceValue(Assert.Single(result.Events),
                "dns.distinctSuspiciousTxtNames"));
        }
    }

    [Fact]
    public void Legacy_Dns_Rules_Reject_Unattributed_Wire_Only_Records()
    {
        var record = WireRecord("10.250.23.82", NewRoot("legacy"), BinaryLabel(0));
        var context = new RuleEvaluationContext(record, Sensitivity.Balanced, BaseTime);

        // The shared structural predicate remains deny-by-default. Only
        // R102 may opt into validated raw wire-label evidence.
        Assert.False(NetworkBatch096100Evidence.Dns(context));
        Assert.True(NetworkBatch096100Evidence.Dns(context, allowWireName: true));
    }

    [Fact]
    public void Diagnostics_Report_Wire_Name_Without_Qname_Missing()
    {
        var record = WireRecord("10.250.23.83", NewRoot("diagnostics"), BinaryLabel(0));
        var originalName = record.DnsQname;
        var originalLabels = record.DnsWireLabelsBase64!.ToArray();

        var codes = DnsReplayTelemetryDiagnostics.Inspect(record);

        Assert.DoesNotContain("DNS_QNAME_MISSING", codes);
        Assert.DoesNotContain("DNS_QNAME_INVALID", codes);
        Assert.Equal(originalName, record.DnsQname);
        Assert.Equal(originalLabels, record.DnsWireLabelsBase64);
        Assert.DoesNotContain(record.Source!, string.Join(",", codes), StringComparison.Ordinal);
        Assert.DoesNotContain(originalLabels[0], string.Join(",", codes), StringComparison.Ordinal);
    }

    [Fact]
    public async Task R102_Wire_Only_Without_Transport_Fails_Closed()
    {
        var record = WireRecord("10.250.23.84", NewRoot("no-transport"), BinaryLabel(0));
        record.IsUdp = false;
        record.IsTcp = false;

        var outcome = await new R102_DNSTunnelingViaLongLabelsRule()
            .EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, BaseTime));

        Assert.False(outcome.Matched);
        Assert.Empty(outcome.Events);
        Assert.Contains("DNS_TRANSPORT_UNATTRIBUTED",
            DnsReplayTelemetryDiagnostics.Inspect(record));
        Assert.False(record.IsUdp);
        Assert.False(record.IsTcp);
    }

    [Theory]
    [InlineData("AR==")] // Noncanonical padding bits.
    [InlineData("not-base64")]
    [InlineData("")]
    public async Task R102_Invalid_Wire_Label_Fails_Closed(string invalid)
    {
        var record = WireRecord("10.250.23.85", NewRoot("invalid"), BinaryLabel(0));
        record.DnsWireLabelsBase64 = new[] { invalid, "Y29t", "ZXhhbXBsZQ==" };

        var outcome = await new R102_DNSTunnelingViaLongLabelsRule()
            .EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, BaseTime));

        Assert.False(outcome.Matched);
        Assert.Empty(outcome.Events);
    }

    [Fact]
    public async Task R102_Does_Not_Use_Base64_Text_Length_As_Wire_Label_Length()
    {
        // Forty wire octets become 56 Base64 characters: a parser that
        // measures encoded text instead of source bytes would cross 50.
        var shortBinary = Enumerable.Range(0, 40).Select(i => (byte)(i * 5 + 7)).ToArray();
        shortBinary[0] = 0x00;
        shortBinary[1] = 0x80;
        shortBinary[2] = 0xff;
        shortBinary[3] = 0x2e;
        shortBinary[4] = 0x5c;
        var record = WireRecord("10.250.23.86", NewRoot("length"), shortBinary);

        var outcome = await new R102_DNSTunnelingViaLongLabelsRule()
            .EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, BaseTime));

        Assert.False(outcome.Matched);
        Assert.Empty(outcome.Events);
    }

    [Fact]
    public async Task R102_Binary_Acme_Validation_Remains_Excluded()
    {
        var record = WireRecord("10.250.23.87", "_acme-challenge." + NewRoot("acme"),
            BinaryLabel(0));
        var outcome = await new R102_DNSTunnelingViaLongLabelsRule()
            .EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, BaseTime));

        Assert.False(outcome.Matched);
        Assert.Empty(outcome.Events);
    }

    private static string NewRoot(string prefix)
        => prefix + "-" + Guid.NewGuid().ToString("N")[..8] + ".example";

    private static byte[] BinaryLabel(int index)
    {
        var label = Encoding.ASCII.GetBytes(HighEntropyLabels[index]);
        label[0] = 0x00;
        label[1] = 0x2e;
        label[2] = 0x5c;
        label[3] = 0x80;
        label[4] = 0xff;
        return label;
    }

    private static TrafficRecord WireRecord(string source, string root, byte[] leftLabel)
    {
        var labels = new[] { Convert.ToBase64String(leftLabel) }
            .Concat(root.Split('.', StringSplitOptions.RemoveEmptyEntries)
                .Select(label => Convert.ToBase64String(Encoding.ASCII.GetBytes(label))))
            .ToArray();
        return new TrafficRecord
        {
            Source = source,
            Destination = "8.8.8.8",
            SourcePort = 53000,
            DestinationPort = 53,
            IpVersion = 4,
            Protocol = "DNS",
            ApplicationProtocol = "DNS",
            ApplicationService = "DNS",
            DnsQname = null,
            DnsQtype = "TXT",
            DnsWireLabelsBase64 = labels,
            IsUdp = true
        };
    }

    private static string EvidenceValue(DetectionEvent evt, string key)
        => evt.StructuredEvidence?.Items.FirstOrDefault(item =>
            string.Equals(item.Key, key, StringComparison.OrdinalIgnoreCase))?.Value
            ?? throw new InvalidOperationException("Missing evidence key: " + key);
}
