// SPDX-License-Identifier: MIT
// GA R461-R470 — SOURCE CANDIDATE — UNVERIFIED.
// 190 authored xUnit invocations (18 source/adversarial/boundary variants and
// one immutable-profile invariant per rule). ZERO executed. Synthetic records
// are not evidence that an authenticated action or outcome was observed.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch461470AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 9, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason, int Port, string Transport,
        string Application, int Threshold, int Confidence, int Window, int Cooldown)[] Rules =
    {
        ("R461", "DHCP_DISTINCT_CLIENT_LEASE_EXHAUSTION_UNAVAILABLE", 67, "UDP", "DHCP", 1, 76, 5, 20),
        ("R462", "DHCP_OFFER_SERVER_AUTHORITY_UNAVAILABLE", 68, "UDP", "DHCP", 1, 76, 5, 20),
        ("R463", "ARP_GRATUITOUS_RATE_BASELINE_UNAVAILABLE", 0, "ARP", "ARP", 4, 76, 5, 20),
        ("R464", "ARP_IP_MAC_BINDING_TRANSITIONS_UNAVAILABLE", 0, "ARP", "ARP", 1, 76, 5, 20),
        ("R465", "IPV6_ROUTER_ADVERTISEMENT_PREFIX_HISTORY_UNAVAILABLE", 0, "ICMPv6", "ICMPv6", 1, 76, 5, 20),
        ("R466", "WIFI_CONTROLLER_IDENTITY_AND_PROBE_OUTCOME_UNAVAILABLE", 443, "TCP", "HTTP", 1, 76, 5, 20),
        ("R467", "CAPWAP_CONTROL_EXCHANGE_AND_CONTROLLER_POLICY_UNAVAILABLE", 5246, "UDP", "CAPWAP", 1, 76, 5, 20),
        ("R468", "BLUETOOTH_GATEWAY_ASSET_ROLE_AND_EGRESS_UNAVAILABLE", 443, "TCP", "TLS", 1, 76, 5, 20),
        ("R469", "ADB_PROTOCOL_HANDSHAKE_AND_ACCESS_POLICY_UNAVAILABLE", 5555, "TCP", "ADB", 1, 76, 5, 20),
        ("R470", "MDM_ENROLLMENT_OUTCOME_BURST_UNAVAILABLE", 443, "TCP", "HTTP", 4, 76, 5, 20)
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
        {
            foreach (var variation in new[]
            {
                "plausible",
                "typed-observation",
                "descriptor-spoof",
                "approved-ops",
                "forged-audit",
                "tls-only",
                "missing-source",
                "missing-destination",
                "malformed-target",
                "secret-placeholder",
                "wrong-direction",
                "wrong-protocol",
                "threshold-burst",
                "claimed-success",
                "duplicate-id",
                "spoofed-service-name",
                "fragmentary-native",
                "after-cooldown"
            })
            {
                yield return new object[] { rule.Id, rule.Reason, rule.Port,
                    rule.Transport, rule.Application, variation };
            }
        }
    }

    private static TrafficRecord Observation(string id, int port, string transport, string application)
    {
        var record = new TrafficRecord
        {
            Id = Guid.Parse("e67b3c6b-6f1a-4e9b-930a-01f7c7df8a9d"),
            Source = "10.64.2.11",
            Destination = "10.64.2.1",
            IpVersion = id == "R465" ? 6 : 4,
            Protocol = transport,
            IsTcp = transport == "TCP",
            IsUdp = transport == "UDP",
            SourcePort = port == 0 ? null : 50321,
            DestinationPort = port == 0 ? null : port,
            ApplicationProtocol = application,
            Info = string.Empty,
            Length = 512,
            L4Len = 128
        };
        switch (id)
        {
            case "R461":
                record.Info = "DHCPDISCOVER";
                break;
            case "R462":
                record.Info = "DHCPOFFER";
                break;
            case "R463":
                record.MacSource = "02:00:00:00:00:01";
                record.Info = "gratuitous ARP";
                break;
            case "R464":
                record.MacSource = "02:00:00:00:00:02";
                record.Info = "duplicate MAC";
                break;
            case "R465":
                record.Source = "fe80::1";
                record.Destination = "ff02::1";
                record.IcmpTypeCode = (ushort)(134 << 8);
                record.Info = "router advertisement prefix change";
                break;
            case "R466":
                record.HttpMethod = "GET";
                record.HttpUri = "/admin";
                record.HttpHost = "controller.example.test";
                break;
            case "R467":
                record.Info = "CAPWAP discovery request";
                break;
            case "R468":
                record.Destination = "203.0.113.20";
                record.Info = "Bluetooth gateway cloud sync";
                break;
            case "R469":
                record.Info = "ADB connect";
                break;
            case "R470":
                record.HttpMethod = "POST";
                record.HttpUri = "/mdm/enroll";
                record.HttpHost = "enroll.example.test";
                break;
        }
        return record;
    }

    private static EvidenceDrivenPrecisionRuleBase CreateRule(string id)
        => id switch
        {
            "R461" => new R461_DHCPStarvationCandidateRule(),
            "R462" => new R462_DHCPRogueOfferDetectedRule(),
            "R463" => new R463_ARPGratuitousStormRule(),
            "R464" => new R464_ARPDuplicateMACFlipFlopRule(),
            "R465" => new R465_IPv6SLAACPrefixChangeRule(),
            "R466" => new R466_WiFiControllerAdminProbeRule(),
            "R467" => new R467_CAPWAPExternalControllerAttemptRule(),
            "R468" => new R468_BluetoothGatewayInternetEgressRule(),
            "R469" => new R469_AndroidDebugBridgeNetworkAccessRule(),
            "R470" => new R470_MobileMDMEnrollmentBurstRule(),
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
    public async Task Untrusted_Network_Control_Clues_Cannot_Claim_A_Validated_Outcome(
        string id, string reason, int port, string transport, string application, string variation)
    {
        var record = Observation(id, port, transport, application);
        switch (variation)
        {
            case "typed-observation":
                // Preserve the original wire-derived clue, but never infer
                // authenticated outcome, asset role or anomaly baseline.
                Assert.NotNull(record.ApplicationProtocol);
                break;
            case "descriptor-spoof":
                record.Info = id + " verified anonymous login, successful print or enumeration";
                break;
            case "approved-ops":
                record.ProcessName = "approved-inventory.exe";
                record.Info = "approved DHCP maintenance, HA failover, Wi-Fi controller polling, MDM enrollment";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Trusted-Controller: true\r\n" +
                    "X-Authenticated-Audit: true\r\nX-Enrollment-Succeeded: true";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpHost = null;
                record.DnsQname = null;
                record.DnsQtype = null;
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
            case "malformed-target":
                record.HttpUri = "/%ZZ/%00";
                record.DnsQname = "malformed..local";
                record.Info = "truncated discovery frame";
                break;
            case "secret-placeholder":
                record.HttpUri = "/?token=synthetic-not-a-real-credential";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-not-a-real-credential";
                break;
            case "wrong-direction":
                record.Source = "10.94.2.11";
                record.Destination = "10.94.2.10";
                break;
            case "wrong-protocol":
                record.Protocol = transport == "TCP" ? "UDP" : "TCP";
                record.IsTcp = transport != "TCP";
                record.IsUdp = transport == "TCP";
                break;
            case "threshold-burst":
                // Even the four-observation defaults R463/R470
                // cannot be satisfied by uncorroborated request shapes.
                for (var i = 0; i < 5; i++)
                    AssertMissingProducer(await Evaluate(id,
                        Observation(id, port, transport, application), i * 10), reason);
                break;
            case "claimed-success":
                record.Info = "DHCP lease exhausted; rogue server verified; ADB authorized; MDM enrolled";
                break;
            case "duplicate-id":
                var duplicate = Observation(id, port, transport, application);
                duplicate.Id = record.Id;
                AssertMissingProducer(await Evaluate(id, duplicate, 20), reason);
                break;
            case "spoofed-service-name":
                record.HttpHost = "claimed-" + id.ToLowerInvariant() + ".example.test";
                record.ProcessName = "verified-mdm-controller.exe";
                record.ApplicationService = "approved-dhcp-server";
                break;
            case "fragmentary-native":
                record.Length = 1;
                record.L4Len = 1;
                record.Info = "DHCP OFFER; gratuitous ARP; SLAAC prefix; CAPWAP; ADB";
                break;
            case "after-cooldown":
                AssertMissingProducer(await Evaluate(id,
                    Observation(id, port, transport, application), 0), reason);
                AssertMissingProducer(await Evaluate(id,
                    Observation(id, port, transport, application), 21 * 60), reason);
                break;
        }

        var result = await Evaluate(id, record, variation == "after-cooldown" ? 42 * 60 : 60);
        if (variation == "missing-source" || variation == "missing-destination")
        {
            Assert.False(result.Matched);
            Assert.Empty(result.Events);
            Assert.Contains(result.NoMatchReasons, item => item.Code == "MISSING_CORE_TELEMETRY");
        }
        else
        {
            AssertMissingProducer(result, reason);
        }
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        yield return new object[] { "R461", 1, 76, 5, 20 };
        yield return new object[] { "R462", 1, 76, 5, 20 };
        yield return new object[] { "R463", 4, 76, 5, 20 };
        yield return new object[] { "R464", 1, 76, 5, 20 };
        yield return new object[] { "R465", 1, 76, 5, 20 };
        yield return new object[] { "R466", 1, 76, 5, 20 };
        yield return new object[] { "R467", 1, 76, 5, 20 };
        yield return new object[] { "R468", 1, 76, 5, 20 };
        yield return new object[] { "R469", 1, 76, 5, 20 };
        yield return new object[] { "R470", 4, 76, 5, 20 };
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
