// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R276AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch276280Context.Sample();
    private static async Task<bool> Hit(TrafficRecord r, double s = 0)
        => (await new R276_OAuthConsentGrantAbuseIndicatorRule()
            .EvaluateAsync(NetworkBatch276280Context.At(r, s))).Matched;
    [Fact] public async Task AdminConsent_Uri_Is_Not_Approved_Grant() {
        var r = Sample(); r.HttpUri = "/adminconsent?client_id=app"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Scope_Query_Is_Not_Granted_Permission() {
        var r = Sample(); r.HttpUri = "/authorize?scope=Mail.Read%20offline_access";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Consent_Text_In_Info_Is_Not_IdP_Audit() {
        var r = Sample(); r.Info = "OAuth admin consent granted"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Graph_Host_Is_Not_Grant_Outcome() {
        var r = Sample(); r.HttpHost = "graph.microsoft.com"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Client_Process_Name_Is_Not_A_Grant() {
        var r = Sample(); r.ProcessName = "consent-granted.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Request_Is_Not_Distinct_Grant() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Out_Of_Order_Requests_Are_Not_Grant_Sequence() {
        var r = Sample(); Assert.False(await Hit(r, 30)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Missing_Actor_Is_Not_Inferred_From_IP() {
        var r = Sample(); r.Source = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Transport_Does_Not_Prove_Consent() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Query_Secret_Is_Not_Emitted_As_Grant_Evidence() {
        var r = Sample(); r.HttpUri += "?code=private-secret";
        var result = await new R276_OAuthConsentGrantAbuseIndicatorRule()
            .EvaluateAsync(NetworkBatch276280Context.At(r));
        Assert.False(result.Matched); Assert.Empty(result.Events);
    }
    [Fact] public void High_Floor_Mode_And_Threshold_Preserved() {
        var p = new R276_OAuthConsentGrantAbuseIndicatorRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
