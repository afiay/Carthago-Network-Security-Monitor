// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R257AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch256260Context.Sample(257);
    private static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => NetworkBatch256260Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R257_ExfiltrationAfterCredentialAlertChainRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Exact_Credential_Tool_And_Parsed_External_Upload_Coobserved()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Unattributed_Process_Does_Not_Imply_Credential_Alert() {
        var r = Sample(); r.ProcessName = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Packet_Info_Cannot_Forge_Credential_Alert() {
        var r = Sample(); r.ProcessName = "curl.exe"; r.Info = "credential alert mimikatz";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Process_Substring_Is_Not_Trusted() {
        var r = Sample(); r.ProcessName = "notmimikatz.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Destination_Is_Benign() {
        var r = Sample(); r.Destination = "10.57.0.20"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Http_Get_Is_Not_An_Upload_Request() {
        var r = Sample(); r.HttpMethod = "GET"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Missing_Content_Length_Is_Rejected() {
        var r = Sample(); r.HttpRequestHeaders = "Host: upload.example"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Tls_Contradiction_Is_Rejected() {
        var r = Sample(); r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Are_Rejected() {
        var rule = new R257_ExfiltrationAfterCredentialAlertChainRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 21))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }
    [Fact] public async Task Secret_Path_Is_Redacted_And_Chain_Unverified() {
        var r = Sample(); r.HttpUri = "/private-secret-marker/upload";
        var result = await new R257_ExfiltrationAfterCredentialAlertChainRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain("private-secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
        Assert.Contains("alert chain unverified", evt.Summary ?? "", StringComparison.OrdinalIgnoreCase);
    }
    [Fact] public void Original_Critical_Alert_Confidence_Remains() {
        var p = new R257_ExfiltrationAfterCredentialAlertChainRule().PrecisionProfile;
        Assert.Equal(88, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
