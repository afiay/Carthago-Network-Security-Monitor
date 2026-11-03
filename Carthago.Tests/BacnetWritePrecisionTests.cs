using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Services.EnvironmentTuning;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;
using Carthago.Tests.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;

public sealed class BacnetWritePrecisionTests
{
    internal static TrafficRecord Parse(byte[] payload, bool reverse = false,
        bool privateSource = false, string? sourceOverride = null,
        bool sameServicePort = false, int declaredLengthExtra = 0)
    {
        var raw = new byte[28 + payload.Length];
        raw[0] = 0x45;
        raw[2] = (byte)((raw.Length + declaredLengthExtra) >> 8);
        raw[3] = (byte)(raw.Length + declaredLengthExtra);
        raw[8] = 64;
        raw[9] = 17;
        IPAddress.Parse(reverse ? "10.20.0.66" : privateSource ? "10.21.0.44" : sourceOverride ?? "203.0.113.44")
            .GetAddressBytes().CopyTo(raw, 12);
        IPAddress.Parse(reverse ? "203.0.113.44" : "10.20.0.66").GetAddressBytes().CopyTo(raw, 16);
        int sourcePort = reverse || sameServicePort ? 47808 : 48000;
        int destinationPort = reverse ? 48000 : 47808;
        raw[20] = (byte)(sourcePort >> 8);
        raw[21] = (byte)sourcePort;
        raw[22] = (byte)(destinationPort >> 8);
        raw[23] = (byte)destinationPort;
        raw[24] = (byte)((payload.Length + 8) >> 8);
        raw[25] = (byte)(payload.Length + 8);
        payload.CopyTo(raw, 28);
        return Assert.IsType<TrafficRecord>(new PacketHandler().ParseFrame(raw, (PacketDotNet.LinkLayers)12));
    }

    [Fact]
    public async Task CapturedConfirmedWritePropertyProducesShadowCandidateNotWriteSuccess()
    {
        var record = Parse(BacnetWritePropertyInspectorTests.Request());
        Assert.True(record.BacnetWritePropertyRequestObserved);
        Assert.Equal("bacnet.writeproperty.request", record.ApplicationProtocol);
        var rule = new R485_BACnetWritePropertyRequestRule();
        Assert.Equal(RuleRuntimeMode.Alert, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(RulePrecisionMaturity.Candidate, rule.PrecisionProfile.Maturity);
        Assert.Equal(86, rule.PrecisionProfile.MinimumConfidence);
        Assert.True(RulePrecisionCatalog.HasField("capture_only_bacnet_writeproperty", record));
        Assert.True(RulePrecisionCatalog.Validate("R485", record).CanEvaluate);
        var result = await rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.True(result.Matched);
        Assert.All(result.Events, evt =>
        {
            Assert.Equal("R485", evt.RuleId);
            Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus);
            Assert.DoesNotContain("write_succeeded", evt.Evidence ?? string.Empty);
        });
    }

    [Fact]
    public async Task ConfirmedRequestFromStandardBacnetServicePortIsAdmitted()
    {
        var record = Parse(BacnetWritePropertyInspectorTests.Request(),
            sourceOverride: "203.0.113.96", sameServicePort: true);
        Assert.True(record.BacnetWritePropertyRequestObserved);
        var result = await new R485_BACnetWritePropertyRequestRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.True(result.Matched);
        Assert.All(result.Events, evt => Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus));

        var response = Parse(BacnetWritePropertyInspectorTests.Request(apduFlags: 0x20),
            sourceOverride: "203.0.113.97", sameServicePort: true);
        Assert.False(response.BacnetWritePropertyRequestObserved);
    }

    [Fact]
    public void TruncatedCapturedIpLengthDoesNotAttestBacnetDatagram()
    {
        var record = Parse(BacnetWritePropertyInspectorTests.Request(),
            sourceOverride: "203.0.113.98", declaredLengthExtra: 1);
        Assert.False(record.BacnetWritePropertyRequestObserved);
    }

    [Fact]
    public async Task ImportedClaimsCannotForgeBacnetCaptureProvenance()
    {
        var record = JsonSerializer.Deserialize<TrafficRecord>(
            "{\"Source\":\"203.0.113.44\",\"Destination\":\"10.20.0.66\",\"IsUdp\":true,\"DestinationPort\":47808,\"ApplicationProtocol\":\"bacnet.writeproperty.request\",\"BacnetWritePropertyRequestObserved\":true,\"Info\":\"BACnet WriteProperty confirmed\"}");
        Assert.NotNull(record);
        Assert.False(record!.BacnetWritePropertyRequestObserved);
        Assert.False(RulePrecisionCatalog.HasField("capture_only_bacnet_writeproperty", record));
        Assert.False(RulePrecisionCatalog.Validate("R485", record).CanEvaluate);
        var result = await new R485_BACnetWritePropertyRequestRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.False(result.Matched);
    }

    [Fact]
    public async Task ReadPropertyWrongDirectionAndMalformedFramesRemainNoMatch()
    {
        var negative = new[]
        {
            Parse(BacnetWritePropertyInspectorTests.Request(service: 0x0c)),
            Parse(BacnetWritePropertyInspectorTests.Request(), reverse: true),
            Parse(BacnetWritePropertyInspectorTests.Request(apduFlags: 0x08))
        };
        var rule = new R485_BACnetWritePropertyRequestRule();
        foreach (var item in negative)
        {
            Assert.False(item.BacnetWritePropertyRequestObserved);
            Assert.False((await rule.EvaluateAsync(
                new RuleEvaluationContext(item, Sensitivity.Balanced, DateTime.UtcNow))).Matched);
        }
    }

    [Fact]
    public async Task ValidWriteOnInternalOnlyNetworkIsNotR485ExternalBoundary()
    {
        var record = Parse(BacnetWritePropertyInspectorTests.Request(), privateSource: true);
        Assert.True(record.BacnetWritePropertyRequestObserved);
        var result = await new R485_BACnetWritePropertyRequestRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task RepeatedCapturedWriteRespectsCooldownAndStaysNonAlerting()
    {
        var at = DateTime.UtcNow;
        var rule = new R485_BACnetWritePropertyRequestRule();
        var first = await rule.EvaluateAsync(new RuleEvaluationContext(
            Parse(BacnetWritePropertyInspectorTests.Request(), sourceOverride: "203.0.113.85"),
            Sensitivity.Balanced, at));
        var second = await rule.EvaluateAsync(new RuleEvaluationContext(
            Parse(BacnetWritePropertyInspectorTests.Request(), sourceOverride: "203.0.113.85"),
            Sensitivity.Balanced, at.AddSeconds(10)));
        Assert.True(first.Matched);
        Assert.True(second.Matched);
        Assert.All(first.Events, evt => Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus));
        Assert.True(second.Suppressed);
        Assert.Empty(second.Events);
    }
    [Theory]
    [InlineData("BACnet ReadProperty request object=analogOutput")]
    [InlineData("BACnet device inventory request")]
    public async Task R485_Does_Not_Interpret_Benign_Bacnet_As_Write(string description)
    {
        var record = new TrafficRecord
        {
            Source = "10.20.0.44", Destination = "10.21.0.66", Protocol = "UDP",
            ApplicationProtocol = "BACnet", DestinationPort = 47808, Info = description
        };

        var result = await new R485_BACnetWritePropertyRequestRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task Unverified_Bacnet_WriteProperty_Text_Cannot_Substitute_For_Confirmed_Apdu()
    {
        var record = new TrafficRecord
        {
            Source = "203.0.113.44", Destination = "10.20.0.66", Protocol = "UDP",
            ApplicationProtocol = "BACnet", DestinationPort = 47808,
            Info = "BACnet WriteProperty request object=analogOutput"
        };
        var rule = new R485_BACnetWritePropertyRequestRule();
        var detection = await rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        // This fixture has only a descriptive Info string, not a parser-decoded
        // confirmed BACnet WriteProperty APDU. It must not produce an event.
        // The missing positive remains visible in the labeled replay benchmark.
        Assert.False(detection.Matched);
        Assert.Empty(detection.Events);
        Assert.Contains(detection.NoMatchReasons,
            reason => reason.Code == "BACNET_WRITEPROPERTY_CONFIRMED_REQUEST_UNAVAILABLE");
    }
}
