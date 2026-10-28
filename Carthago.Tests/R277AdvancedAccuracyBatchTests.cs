// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R277AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() {
        var r = NetworkBatch276280Context.Sample(); r.DestinationPort = 993;
        r.ApplicationProtocol = "IMAP"; r.HttpMethod = null; r.HttpUri = null;
        return r;
    }
    private static async Task<bool> Hit(TrafficRecord r, double s = 0)
        => (await new R277_LegacyProtocolAuthenticationAttemptRule()
            .EvaluateAsync(NetworkBatch276280Context.At(r, s))).Matched;
    [Fact] public async Task Imaps_Port_Alone_Is_Not_Auth_Attempt() => Assert.False(await Hit(Sample()));
    [Fact] public async Task Pop3_Port_Alone_Is_Not_Auth_Attempt() {
        var r = Sample(); r.DestinationPort = 110; Assert.False(await Hit(r));
    }
    [Fact] public async Task Smtp_Submission_Port_Alone_Is_Not_Auth_Attempt() {
        var r = Sample(); r.DestinationPort = 587; Assert.False(await Hit(r));
    }
    [Fact] public async Task Info_Auth_Login_Is_Not_Parsed_Command() {
        var r = Sample(); r.Info = "IMAP AUTH LOGIN"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Protocol_Label_Is_Not_Authenticated_Outcome() {
        var r = Sample(); r.Protocol = "IMAP"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Http_Basic_Header_Is_Not_IMAP_Auth() {
        var r = Sample(); r.HttpRequestHeaders = "Authorization: Basic REDACTED";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Does_Not_Create_Auth() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Create_Auth() {
        var r = Sample(); Assert.False(await Hit(r, 10)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Missing_Destination_Does_Not_Create_Auth() {
        var r = Sample(); r.Destination = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Udp_And_Tcp_Is_Not_Parsed_Auth() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public void Medium_Floor_Mode_And_Threshold_Preserved() {
        var p = new R277_LegacyProtocolAuthenticationAttemptRule().PrecisionProfile;
        Assert.Equal(74, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
