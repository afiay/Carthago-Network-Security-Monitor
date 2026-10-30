// SPDX-License-Identifier: MIT
// GA R471-R480 — SOURCE CANDIDATE — UNVERIFIED.
// 200 authored xUnit invocations: 19 adversarial/boundary cases and
// one immutable-profile contract per rule. ZERO EXECUTED.
// Synthetic TrafficRecord values do not prove a decoded OT command,
// a clipboard file transfer, or an authenticated remote-support session.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch471480AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 10, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason, int Port, string Application,
        int Threshold, int Confidence, int Window, int Cooldown)[] Rules =
    {
        ("R471", "RDP_CLIPBOARD_FILE_CHANNEL_PROVENANCE_UNAVAILABLE", 3389, "RDP", 1, 76, 5, 20),
        ("R472", "REMOTE_SUPPORT_SESSION_AND_ASSET_POLICY_UNAVAILABLE", 5938, "TLS", 1, 76, 5, 20),
        ("R473", "MODBUS_DEVICE_ID_REQUEST_SERIES_UNAVAILABLE", 502, "modbus", 4, 86, 10, 45),
        ("R474", "MODBUS_LISTEN_ONLY_SUBFUNCTION_UNAVAILABLE", 502, "modbus", 1, 86, 10, 45),
        ("R475", "MODBUS_DIAGNOSTICS_SUBFUNCTION_AND_POLICY_UNAVAILABLE", 502, "modbus", 1, 86, 10, 45),
        ("R476", "MODBUS_COIL_WRITE_DISTINCT_BURST_UNAVAILABLE", 502, "modbus.write", 4, 86, 10, 45),
        ("R477", "S7_CPU_CONTROL_COMMAND_UNAVAILABLE", 102, "s7comm", 1, 86, 10, 45),
        ("R478", "S7_BLOCK_TRANSFER_OPERATION_UNAVAILABLE", 102, "s7comm", 1, 86, 10, 45),
        ("R479", "S7_PLC_IDENTIFICATION_REQUEST_UNAVAILABLE", 102, "s7comm", 1, 86, 10, 45),
        ("R480", "DNP3_CROB_CONTROL_OPERATION_UNAVAILABLE", 20000, "dnp3", 1, 86, 10, 45)
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
        {
            foreach (var variation in new[]
            {
                "plausible",
                "wire-framing",
                "descriptor-spoof",
                "approved-engineering",
                "forged-audit",
                "tls-only",
                "missing-source",
                "missing-destination",
                "malformed-command",
                "secret-placeholder",
                "wrong-direction",
                "wrong-protocol",
                "threshold-burst",
                "claimed-success",
                "duplicate-id",
                "spoofed-process",
                "fragmentary-native",
                "after-cooldown",
                "cross-boundary"
            })
                yield return new object[] { rule.Id, rule.Reason, rule.Port, rule.Application, variation };
        }
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
            Info = id + " claimed operation",
            Length = 512,
            L4Len = 128
        };

    private static EvidenceDrivenPrecisionRuleBase CreateRule(string id)
        => id switch
        {
            "R471" => new R471_RDPClipboardFileTransferIndicatorRule(),
            "R472" => new R472_RemoteSupportToolUnexpectedUseRule(),
            "R473" => new R473_ModbusFunction43DeviceIdEnumerationRule(),
            "R474" => new R474_ModbusForceListenOnlyModeAttemptRule(),
            "R475" => new R475_ModbusDiagnosticsFunctionAbuseRule(),
            "R476" => new R476_ModbusCoilWriteBurstRule(),
            "R477" => new R477_S7StartStopCPUCommandIndicatorRule(),
            "R478" => new R478_S7UploadDownloadBlockTransferRule(),
            "R479" => new R479_S7PLCIdentificationProbeRule(),
            "R480" => new R480_DNP3ControlRelayOutputBlockRule(),
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
    public async Task Untrusted_Protocol_Or_Session_Clues_Cannot_Assert_Validated_Operations(
        string id, string reason, int port, string application, string variation)
    {
        var record = Observation(id, port, application);
        switch (variation)
        {
            case "wire-framing":
                // Existing OT classifier can attest protocol framing, not
                // the command function/subfunction or successful outcome.
                Assert.NotNull(record.ApplicationProtocol);
                break;
            case "descriptor-spoof":
                record.Info = id + " verified control executed; clipboard file transferred";
                break;
            case "approved-engineering":
                record.ProcessName = "approved-engineering-station.exe";
                record.Info = "approved PLC maintenance and remote support session";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Authenticated-OT-Command: true\r\n" +
                    "X-Authorized-Session: true\r\nX-Operation-Succeeded: true";
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
                record.Info = "truncated command 0x2B/0x0E invalid PDU length";
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
                record.Info = "DNP3 CROB OPERATE succeeded; S7 STOP accepted; RDP clipboard file transfer complete";
                break;
            case "duplicate-id":
                var duplicate = Observation(id, port, application);
                duplicate.Id = record.Id;
                AssertMissingProducer(await Evaluate(id, duplicate, 20), reason);
                break;
            case "spoofed-process":
                record.ProcessName = "s7comm-modbus-control-verified.exe";
                record.ApplicationService = "trusted-plc";
                break;
            case "fragmentary-native":
                record.Length = 1;
                record.L4Len = 1;
                record.ApplicationProtocol = "modbus";
                break;
            case "after-cooldown":
                AssertMissingProducer(await Evaluate(id, Observation(id, port, application), 0), reason);
                AssertMissingProducer(await Evaluate(id, Observation(id, port, application), 46 * 60), reason);
                break;
            case "cross-boundary":
                record.Destination = "203.0.113.20";
                break;
        }

        var result = await Evaluate(id, record, variation == "after-cooldown" ? 92 * 60 : 60);
        if (variation is "missing-source" or "missing-destination")
        {
            Assert.False(result.Matched);
            Assert.Empty(result.Events);
            Assert.Contains(result.NoMatchReasons, item => item.Code == "MISSING_CORE_TELEMETRY");
        }
        else
            AssertMissingProducer(result, reason);
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        yield return new object[] { "R471", 1, 76, 5, 20 };
        yield return new object[] { "R472", 1, 76, 5, 20 };
        yield return new object[] { "R473", 4, 86, 10, 45 };
        yield return new object[] { "R474", 1, 86, 10, 45 };
        yield return new object[] { "R475", 1, 86, 10, 45 };
        yield return new object[] { "R476", 4, 86, 10, 45 };
        yield return new object[] { "R477", 1, 86, 10, 45 };
        yield return new object[] { "R478", 1, 86, 10, 45 };
        yield return new object[] { "R479", 1, 86, 10, 45 };
        yield return new object[] { "R480", 1, 86, 10, 45 };
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
