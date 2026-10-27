// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R150AdvancedAccuracyBatchTests
{
    [Fact] public async Task Parsed_Fingerprint_Plus_Labeled_Summary_Matches()
    {
        var r = NetworkBatch146150Context.Tls(); r.Info = "cobalt strike ja3 label from enrichment";
        var result = await new R150_KnownMalwareLikeTlsFingerprintLabelRule().EvaluateAsync(NetworkBatch146150Context.At(r));
        Assert.True(result.Matched); Assert.Equal("R150", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Label_Without_Ja3_Ja4_Is_Not_Evidence()
    {
        var r = NetworkBatch146150Context.Tls(); r.Ja4 = null; r.Info = "cobalt strike ja3 label from enrichment";
        Assert.False((await new R150_KnownMalwareLikeTlsFingerprintLabelRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Fingerprint_Without_Family_Label_Is_Benign()
    {
        Assert.False((await new R150_KnownMalwareLikeTlsFingerprintLabelRule().EvaluateAsync(
            NetworkBatch146150Context.At(NetworkBatch146150Context.Tls()))).Matched);
    }

    [Fact] public async Task Malware_Word_Only_In_Host_Does_Not_Declare_Threat_Intel()
    {
        var r = NetworkBatch146150Context.Tls("malware-ja3.example.test");
        Assert.False((await new R150_KnownMalwareLikeTlsFingerprintLabelRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Invalid_Udp_Transport_Is_Rejected()
    {
        var r = NetworkBatch146150Context.Tls(); r.Info = "cobalt strike ja3"; r.IsTcp = false; r.IsUdp = true;
        Assert.False((await new R150_KnownMalwareLikeTlsFingerprintLabelRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Huge_Untrusted_Packet_Summary_Does_Not_Qualify()
    {
        var r = NetworkBatch146150Context.Tls(); r.Info = new string('x', 2048) + " cobalt strike ja3";
        Assert.False((await new R150_KnownMalwareLikeTlsFingerprintLabelRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Info_Label_On_Plain_Tcp_Is_Not_Tls_Provenance()
    {
        var r = NetworkBatch146150Context.Tls(); r.Info = "cobalt strike ja3";
        r.Protocol = "TCP"; r.ApplicationProtocol = "TCP"; r.ApplicationService = "TCP";
        Assert.False((await new R150_KnownMalwareLikeTlsFingerprintLabelRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public void Existing_High_Risk_Alert_Mode_And_88_Floor_Are_Unchanged()
    {
        var p = new R150_KnownMalwareLikeTlsFingerprintLabelRule().PrecisionProfile;
        Assert.Equal(88, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
