// SPDX-License-Identifier: MIT
// GA R511-R520 — SOURCE CANDIDATE — UNVERIFIED.
// 250 concrete xUnit invocations AUTHORED, ZERO EXECUTED:
// 24 independent synthetic adversarial/boundary variants and one profile
// invariant for each of ten existing rules. No authenticated audit is faked.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch511520AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 15, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason, string Host, string Application,
        string? Method, string? Path, int Port)[] Rules =
    {
        ("R511", "DB_EXPORT_PROCESS_FILE_AND_UPLOAD_CORRELATION_UNAVAILABLE", "uploads.example.test", "http", "POST", "/archive/upload", 443),
        ("R512", "SENSITIVE_FILE_PERSONAL_EMAIL_DELIVERY_PROVENANCE_UNAVAILABLE", "mail.example.test", "http", "POST", "/mail/send", 443),
        ("R513", "SSH_DYNAMIC_FORWARD_COMMAND_AND_SOCKET_PROVENANCE_UNAVAILABLE", "ssh.example.test", "ssh", null, null, 22),
        ("R514", "CHISEL_AUTHENTICATED_HANDSHAKE_PROVENANCE_UNAVAILABLE", "tunnel.example.test", "http", "GET", "/tunnel", 8080),
        ("R515", "FRP_AUTHENTICATED_HANDSHAKE_PROVENANCE_UNAVAILABLE", "frp.example.test", "tcp", null, null, 7000),
        ("R516", "CLOUDFLARED_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE", "edge.example.test", "quic", null, null, 7844),
        ("R517", "NGROK_AGENT_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE", "ngrok-free.app", "http", "GET", "/api/tunnels", 443),
        ("R518", "SSH_REVERSE_FORWARD_COMMAND_AND_LISTENER_PROVENANCE_UNAVAILABLE", "ssh.example.test", "ssh", null, null, 22),
        ("R519", "DOQ_ALPN_RESOLVER_IDENTITY_AND_APPROVAL_UNAVAILABLE", "resolver.example.test", "quic", null, null, 853),
        ("R520", "MASQUE_CONNECT_UDP_HTTP3_SESSION_PROVENANCE_UNAVAILABLE", "proxy.example.test", "http", "CONNECT", "/.well-known/masque/udp/target/443", 443),
    };

    private static readonly string[] Variations =
    {
        "plausible",
        "descriptor-spoof",
        "approved-admin",
        "forged-audit",
        "tls-only",
        "missing-source",
        "missing-destination",
        "malformed-target",
        "synthetic-secret",
        "inbound",
        "wrong-protocol",
        "threshold-burst",
        "claimed-success",
        "duplicate-id",
        "spoofed-process",
        "ssh-banner-only",
        "quic-version-only",
        "after-cooldown",
        "provider-lookalike",
        "request-only",
        "response-only",
        "fake-masque",
        "out-of-order",
        "sensitive-uri",
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
            foreach (var variation in Variations)
                yield return new object[] { rule.Id, rule.Reason, rule.Host, rule.Application,
                    rule.Method, rule.Path, rule.Port, variation };
    }

    private static TrafficRecord Observation(string id, string host, string application,
        string? method, string? path, int port)
        => new()
        {
            Id = Guid.Parse("a57f2d61-8f45-489a-9ef7-1b1d4c11b12a"),
            Source = "10.64.2.11",
            Destination = "203.0.113.20",
            IpVersion = 4,
            Protocol = port is 7844 or 853 ? "UDP" : "TCP",
            IsTcp = port is not (7844 or 853),
            IsUdp = port is 7844 or 853,
            SourcePort = 50321,
            DestinationPort = port,
            ApplicationProtocol = application,
            HttpMethod = method,
            HttpUri = path,
            HttpHost = host,
            ProcessName = id is "R513" or "R518" ? "ssh.exe" :
                id == "R516" ? "cloudflared.exe" : "synthetic-client.exe",
            ProcessId = 1234,
            Sni = host,
            IsQuic = port is 7844 or 853,
            QuicVersion = port is 7844 or 853 ? "v1" : null,
            Info = id + " synthetic claimed tunnel or export success",
            Length = 6 * 1024 * 1024,
            L4Len = 512
        };

    private static EvidenceDrivenPrecisionRuleBase CreateRule(string id)
        => id switch
        {
            "R511" => new R511_DBClientExportThenHTTPUploadRule(),
            "R512" => new R512_SensitiveFilenameToPersonalEmailRule(),
            "R513" => new R513_SSHDynamicSOCKSProxyUseRule(),
            "R514" => new R514_ChiselTunnelHandshakeRule(),
            "R515" => new R515_FRPTunnelHandshakeRule(),
            "R516" => new R516_CloudflaredTunnelHandshakeRule(),
            "R517" => new R517_NgrokTunnelHandshakeV2Rule(),
            "R518" => new R518_ReverseSSHTunnelPatternRule(),
            "R519" => new R519_DNSOverQUICUnapprovedResolverRule(),
            "R520" => new R520_MASQUECONNECTUDPProxyUseRule(),
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
    public async Task Untrusted_Network_Clues_Do_Not_Prove_Export_Forwarding_Or_Tunnel_Outcome(
        string id, string reason, string host, string application, string? method,
        string? path, int port, string variation)
    {
        var record = Observation(id, host, application, method, path, port);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info += " " + id + " verified unauthorized proxy/exfiltration";
                break;
            case "approved-admin":
                record.Info += " approved backup, developer proxy, managed connector and helpdesk operation";
                record.ProcessName = "approved-admin.exe";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Tunnel-Authenticated: true\r\nX-Upload-Complete: true\r\nX-Resolver-Approved: false";
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
                record.Sni = null;
                record.Info = null;
                break;
            case "malformed-target":
                record.HttpUri = "/%zz?token=[REDACTED]";
                record.Length = 1;
                record.L4Len = 0;
                break;
            case "synthetic-secret":
                record.HttpRequestHeaders = "Authorization: [REDACTED]\r\nX-Connector-Token: [REDACTED]";
                record.HttpUri = "/tunnel?token=[REDACTED]";
                break;
            case "inbound":
                record.Source = "203.0.113.20";
                record.Destination = "10.64.2.11";
                break;
            case "wrong-protocol":
                record.Protocol = record.IsTcp ? "UDP" : "TCP";
                record.IsTcp = !record.IsTcp;
                record.IsUdp = !record.IsUdp;
                break;
            case "threshold-burst":
                for (var i = 0; i < 6; i++)
                {
                    var distinct = Observation(id, host, application, method, path, port);
                    distinct.Id = Guid.Parse($"a57f2d61-8f45-489a-9ef7-1b1d4c11b1{i:D2}");
                    AssertMissingProducer(await Evaluate(id, distinct, i * 10), reason);
                }
                break;
            case "claimed-success":
                record.Info += " HTTP 201 / tunnel established / authenticated agent / upload completed";
                break;
            case "duplicate-id":
                AssertMissingProducer(await Evaluate(id,
                    Observation(id, host, application, method, path, port), 20), reason);
                break;
            case "spoofed-process":
                record.ProcessName = "trusted-ssh-cloudflared-ngrok.exe";
                record.ApplicationService = "signed-agent-confirmed";
                break;
            case "ssh-banner-only":
                record.ApplicationProtocol = "SSH";
                record.SshJa4 = "SSH-2.0-synthetic";
                record.Info += " SSH-2.0-OpenSSH_9.0 -D 1080 -R 2222";
                break;
            case "quic-version-only":
                record.Protocol = "UDP";
                record.IsTcp = false;
                record.IsUdp = true;
                record.IsQuic = true;
                record.QuicVersion = "v1";
                record.QuicAlpn = null;
                break;
            case "after-cooldown":
                AssertMissingProducer(await Evaluate(id,
                    Observation(id, host, application, method, path, port)), reason);
                AssertMissingProducer(await Evaluate(id,
                    Observation(id, host, application, method, path, port), 40 * 60), reason);
                break;
            case "provider-lookalike":
                record.Sni = "ngrok-cloudflare-frp.example.test";
                record.HttpHost = record.Sni;
                break;
            case "request-only":
                record.HttpMethod = "CONNECT";
                record.Info += " request-only; no correlated response";
                break;
            case "response-only":
                record.HttpMethod = null;
                record.HttpUri = null;
                record.Info = "HTTP 200 response label without a correlated request";
                break;
            case "fake-masque":
                record.HttpRequestHeaders = ":protocol: connect-udp\r\nCapsule-Protocol: ?1";
                record.HttpUri = "/.well-known/masque/udp/host/443";
                record.Info += " claimed HTTP/3 MASQUE";
                break;
            case "out-of-order":
                AssertMissingProducer(await Evaluate(id,
                    Observation(id, host, application, method, path, port), 120), reason);
                break;
            case "sensitive-uri":
                record.HttpUri = "/send?recipient=personal%40example.test&filename=[REDACTED]";
                record.Info += " claimed database export, sensitive filename and mail delivery";
                break;
        }

        var result = await Evaluate(id, record, variation == "out-of-order" ? 5 :
            variation == "after-cooldown" ? 80 * 60 : 60);
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
        foreach (var rule in Rules)
            yield return new object[] { rule.Id };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Alert_Mode_Confidence_Threshold_Window_And_Cooldown_Remain(string id)
    {
        var profile = CreateRule(id).PrecisionProfile;
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(1, profile.Threshold);
        Assert.Equal(84, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(20), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(35), profile.Cooldown);
    }
}
