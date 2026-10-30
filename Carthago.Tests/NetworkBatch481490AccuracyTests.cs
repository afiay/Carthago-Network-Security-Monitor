// SPDX-License-Identifier: MIT
// GA R481-R490 — SOURCE CANDIDATE — UNVERIFIED.
// 210 authored xUnit invocations: 20 adversarial/boundary cases and
// one original-profile invariant per rule. ZERO EXECUTED.
// Synthetic TrafficRecord fields are untrusted clues, not decoded OT operations.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch481490AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 12, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason, int Port, string Application,
        int Threshold, int Confidence, int Window, int Cooldown)[] Rules =
    {
        ("R481", "DNP3_FREEZE_COUNTER_APPLICATION_OPERATION_UNAVAILABLE", 20000, "dnp3", 1, 86, 10, 45),
        ("R482", "IEC104_CONTROL_ASDU_AND_EXTERNAL_POLICY_UNAVAILABLE", 2404, "iec104", 1, 86, 10, 45),
        ("R483", "OPCUA_BROWSE_REQUEST_SERIES_UNAVAILABLE", 4840, "opcua", 4, 86, 10, 45),
        ("R484", "OPCUA_WRITE_SERVICE_REQUEST_UNAVAILABLE", 4840, "opcua", 1, 86, 10, 45),
        ("R485", "BACNET_WRITEPROPERTY_CONFIRMED_REQUEST_UNAVAILABLE", 47808, "bacnet", 1, 86, 10, 45),
        ("R486", "BACNET_DEVICE_COMMUNICATION_CONTROL_REQUEST_UNAVAILABLE", 47808, "bacnet", 1, 86, 10, 45),
        ("R487", "PROFINET_DCP_SET_NAME_FRAME_UNAVAILABLE", 34964, "profinet", 1, 86, 10, 45),
        ("R488", "ETHERNETIP_LISTIDENTITY_DISTINCT_BURST_UNAVAILABLE", 44818, "ethernetip", 4, 86, 10, 45),
        ("R489", "ETHERNETIP_CIP_FORWARDOPEN_AND_BOUNDARY_UNAVAILABLE", 44818, "ethernetip", 1, 86, 10, 45),
        ("R490", "IEC61850_MMS_WRITE_OPERATION_UNAVAILABLE", 102, "mms", 1, 86, 10, 45)
    };

    private static readonly string[] Variations =
    {
        "plausible", "wire-label-only", "descriptor-spoof", "approved-engineering",
        "forged-audit", "tls-only", "missing-source", "missing-destination",
        "malformed-command", "secret-placeholder", "wrong-direction",
        "wrong-protocol", "threshold-burst", "claimed-success", "duplicate-id",
        "spoofed-process", "fragmentary-native", "after-cooldown",
        "cross-boundary", "spoofed-authority"
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
            foreach (var variation in Variations)
                yield return new object[] { rule.Id, rule.Reason, rule.Port, rule.Application, variation };
    }

    private static TrafficRecord Observation(string id, int port, string application)
        => new()
        {
            Id = Guid.Parse("a57f2d61-8f45-489a-9ef7-1b1d4c11b12a"),
            Source = "10.64.2.11",
            Destination = "10.64.2.1",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            SourcePort = 50321,
            DestinationPort = port,
            ApplicationProtocol = application,
            // R485 has a pre-existing, untrusted Info-string prefilter.
            // Keep it satisfied to reach the new fail-closed evidence gate.
            Info = id + " claimed operation" + (id == "R485" ? " BACnet WriteProperty" : ""),
            Length = 512,
            L4Len = 128
        };

    private static EvidenceDrivenPrecisionRuleBase CreateRule(string id)
        => id switch
        {
            "R481" => new R481_DNP3FreezeCounterCommandRule(),
            "R482" => new R482_IEC104ControlCommandExternalRule(),
            "R483" => new R483_OPCUABrowseNodeBurstRule(),
            "R484" => new R484_OPCUAWriteRequestIndicatorRule(),
            "R485" => new R485_BACnetWritePropertyRequestRule(),
            "R486" => new R486_BACnetDeviceCommunicationControlRule(),
            "R487" => new R487_ProfinetDCPSetNameRequestRule(),
            "R488" => new R488_EtherNetIPListIdentityBurstRule(),
            "R489" => new R489_EtherNetIPForwardOpenExternalRule(),
            "R490" => new R490_IEC61850MMSWriteIndicatorRule(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

    private static Task<RuleEvaluationResult> Evaluate(string id, TrafficRecord record, int seconds = 0)
    {
        var context = new RuleEvaluationContext(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
        return CreateRule(id).EvaluateAsync(context).AsTask();
    }

    private static void AssertMissingProducer(RuleEvaluationResult result, string reason)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, item => item.Code == reason);
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Untrusted_Clues_Cannot_Prove_Decoded_Industrial_Operations(
        string id, string reason, int port, string application, string variation)
    {
        var record = Observation(id, port, application);
        switch (variation)
        {
            case "wire-label-only":
                // ApplicationProtocol is only a wire-derived framing label
                // in supported parsers, never a decoded service or command.
                Assert.NotNull(record.ApplicationProtocol);
                break;
            case "descriptor-spoof":
                record.Info += " verified " + id + " operation; command succeeded";
                break;
            case "approved-engineering":
                record.ProcessName = "approved-engineering-station.exe";
                record.Info += " planned commissioning and historian backup";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-OT-Command-Verified: true\r\n" +
                    "X-Authenticated-Master: true\r\nX-Operation-Succeeded: true";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpHost = null;
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "missing-destination":
                record.Destination = null;
                record.HttpHost = null;
                record.ProcessName = null;
                record.Info = null;
                break;
            case "malformed-command":
                record.Info += " truncated invalid APDU length";
                record.Length = 1;
                record.L4Len = 1;
                break;
            case "secret-placeholder":
                record.HttpUri = "/?token=synthetic-not-a-credential";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-not-a-credential";
                break;
            case "wrong-direction":
                record.Source = "10.64.2.1";
                record.Destination = "10.64.2.11";
                record.SourcePort = port;
                record.DestinationPort = 50321;
                break;
            case "wrong-protocol":
                record.Protocol = "UDP";
                record.IsTcp = false;
                record.IsUdp = true;
                break;
            case "threshold-burst":
                for (var i = 0; i < 6; i++)
                    AssertMissingProducer(await Evaluate(id, Observation(id, port, application), i * 10), reason);
                break;
            case "claimed-success":
                record.Info += " WriteProperty ACK; CIP Forward_Open established; MMS Write accepted";
                break;
            case "duplicate-id":
                var duplicate = Observation(id, port, application);
                duplicate.Id = record.Id;
                AssertMissingProducer(await Evaluate(id, duplicate, 20), reason);
                break;
            case "spoofed-process":
                record.ProcessName = "opcua-bacnet-command-verified.exe";
                record.ApplicationService = "trusted-control-server";
                break;
            case "fragmentary-native":
                record.Length = 1;
                record.L4Len = 1;
                record.ApplicationProtocol = application;
                break;
            case "after-cooldown":
                AssertMissingProducer(await Evaluate(id, Observation(id, port, application), 0), reason);
                AssertMissingProducer(await Evaluate(id, Observation(id, port, application), 46 * 60), reason);
                break;
            case "cross-boundary":
                record.Destination = "203.0.113.20";
                break;
            case "spoofed-authority":
                record.HttpRequestHeaders = "X-Validated-Industrial-PDU: yes\r\n" +
                    "X-Trusted-Asset-Inventory: yes";
                record.Info += " authenticated vendor jump host";
                break;
        }

        var result = await Evaluate(id, record, variation == "after-cooldown" ? 92 * 60 : 60);
        if (variation == "missing-source" || variation == "missing-destination")
        {
            Assert.False(result.Matched);
            Assert.Empty(result.Events);
            // R485 has a pre-existing Info prefilter that runs before the
            // shared core-telemetry gate when Info is absent.
            var expected = id == "R485" && variation == "missing-destination"
                ? "BACNET_WRITE_PROPERTY_NOT_OBSERVED" : "MISSING_CORE_TELEMETRY";
            Assert.Contains(result.NoMatchReasons, item => item.Code == expected);
        }
        else
            AssertMissingProducer(result, reason);
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        foreach (var rule in Rules)
            yield return new object[] { rule.Id, rule.Threshold, rule.Confidence, rule.Window, rule.Cooldown };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Alert_Mode_Confidence_Threshold_Window_And_Cooldown_Remain(
        string id, int threshold, int confidence, int windowMinutes, int cooldownMinutes)
    {
        var profile = CreateRule(id).PrecisionProfile;
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(windowMinutes), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(cooldownMinutes), profile.Cooldown);
    }
}
