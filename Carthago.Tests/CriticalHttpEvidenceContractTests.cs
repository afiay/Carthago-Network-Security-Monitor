// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using System.Text;
using Carthago.Services;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.Payloads;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class CriticalHttpEvidenceContractTests
{
    private static RuleEvaluationContext Context(TrafficRecord record)
        => new(record, Sensitivity.Balanced, DateTime.UtcNow);

    private static TrafficRecord Http(string uri, string info = "") => new()
    {
        Source = "192.0.2.30", Destination = "192.0.2.50",
        DestinationPort = 80, Protocol = "TCP", ApplicationProtocol = "HTTP",
        HttpMethod = "GET", HttpHost = "camera-lab.internal",
        HttpUri = uri, Info = info, ProcessName = "browser.exe"
    };

    [Fact]
    public async Task R092_Benign_Camera_Admin_And_Malware_Words_In_Notes_Do_Not_Alert()
    {
        var record = Http("/admin", "routine camera administration; malware scan complete");
        Assert.False((await new R092_KnownMalwareHTTPURIPatternRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R092_Explicit_C2_Endpoint_Remains_Detected()
    {
        var record = Http("/gate.php", "HTTP request observed");
        // Explicit parsed HTTP request telemetry, not a URI on an unclassified packet.
        record.IsTcp = true;
        record.SourcePort = 50000;
        record.Length = 256;
        Assert.True((await new R092_KnownMalwareHTTPURIPatternRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R365_Generic_Cloud_Metadata_Token_Request_Does_Not_Alert()
    {
        var record = Http("/latest/api/token", "AWS metadata token negotiation");
        record.HttpHost = "169.254.169.254";
        record.Destination = "169.254.169.254";
        Assert.False((await new R365_HashiCorpVaultTokenInHTTPRule().EvaluateAsync(Context(record))).Matched);
    }

    [Fact]
    public async Task R365_Observed_Vault_Token_Still_Produces_A_Detection()
    {
        const string syntheticToken = "hvs.ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
        var wire = "GET /v1/auth/token/lookup-self HTTP/1.1\r\n"
            + "Host: vault.internal\r\nX-Vault-Token: " + syntheticToken + "\r\n\r\n";
        Assert.True(HttpLight.TryParseHttp(Encoding.ASCII.GetBytes(wire), out var parsed));
        Assert.True(parsed.ObservedVaultTokenPattern);
        var record = Http(parsed.Path!, string.Empty);
        record.IsTcp = true;
        record.SourcePort = 50000;
        record.HttpMethod = parsed.Method;
        record.HttpHost = parsed.Host;
        record.HttpRequestHeaders = parsed.JoinedHeaderLines;
        record.HttpVaultTokenPatternObserved = parsed.ObservedVaultTokenPattern;
        var result = await new R365_HashiCorpVaultTokenInHTTPRule().EvaluateAsync(Context(record));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(syntheticToken, evt.Evidence ?? string.Empty);
        Assert.DoesNotContain(syntheticToken, evt.Summary ?? string.Empty);
    }
}
