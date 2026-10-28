// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R275AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch271275Context.DeviceCodeRequest();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R275_OAuthDeviceCodePhishingIndicatorRule()
            .EvaluateAsync(NetworkBatch271275Context.At(r, seconds));
    [Fact] public async Task Synthetic_Device_And_User_Code_Query_Is_Not_Trusted_Phishing() {
        Assert.False((await Evaluate(Sample())).Matched);
    }
    [Fact] public async Task Routine_Device_Code_Initiation_Is_Benign() {
        var r = Sample(); r.HttpUri = "/oauth2/v2.0/devicecode?client_id=app&scope=openid";
        Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task User_Code_Only_Is_Not_Phishing() {
        var r = Sample(); r.HttpUri = "/oauth2/v2.0/devicecode?user_code=123";
        Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task Device_Code_Only_Is_Not_Phishing() {
        var r = Sample(); r.HttpUri = "/oauth2/v2.0/devicecode?device_code=abc";
        Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task Packet_Info_Spoof_Is_Not_IdP_Audit() {
        var r = Sample(); r.HttpUri = null; r.Info = "device_code=abc user_code=xyz phishing";
        Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task IdP_Lookalike_Host_Does_Not_Prove_Phishing() {
        var r = Sample(); r.HttpHost = "login.microsoftonline.com.attacker.test";
        Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task Query_Tokens_Do_Not_Attest_User_Consent() {
        var r = Sample(); r.HttpUri += "&consent=granted";
        Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task TLS_Sni_Is_Not_Decrypted_Device_Flow_Audit() {
        var r = Sample(); r.HttpUri = null; r.Sni = "login.microsoftonline.com";
        Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Does_Not_Create_Phishing_Event() {
        var r = Sample(); Assert.False((await Evaluate(r)).Matched);
        Assert.False((await Evaluate(r, 1)).Matched);
    }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Create_Phishing_Event() {
        var r = Sample(); Assert.False((await Evaluate(r, 10)).Matched);
        Assert.False((await Evaluate(r, 1)).Matched);
    }
    [Fact] public async Task Query_Secrets_Are_Not_Emitted_As_Evidence() {
        var r = Sample(); r.HttpUri += "&secret=private-token";
        var result = await Evaluate(r);
        Assert.False(result.Matched); Assert.Empty(result.Events);
    }
    [Fact] public async Task Contradictory_Udp_Https_Metadata_Fails_Closed() {
        var r = Sample(); r.IsUdp = true; Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public void High_Floor_Mode_And_Single_Observation_Threshold_Preserved() {
        var p = new R275_OAuthDeviceCodePhishingIndicatorRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
