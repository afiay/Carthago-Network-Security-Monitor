// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R147AdvancedAccuracyBatchTests
{
    [Fact] public async Task Explicit_Encrypted_Client_Hello_Summary_Matches()
    {
        var r = NetworkBatch146150Context.Tls(); r.Info = "encrypted client hello negotiated";
        var result = await new R147_EncryptedClienthelloOrEchIndicatorRule().EvaluateAsync(NetworkBatch146150Context.At(r));
        Assert.True(result.Matched); Assert.Equal("R147", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Explicit_Underscore_Variant_Matches()
    {
        var r = NetworkBatch146150Context.Tls(); r.Info = "encrypted_client_hello flag observed";
        Assert.True((await new R147_EncryptedClienthelloOrEchIndicatorRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Ordinary_Tls_Without_Ech_Is_Not_Flagged()
    {
        Assert.False((await new R147_EncryptedClienthelloOrEchIndicatorRule().EvaluateAsync(
            NetworkBatch146150Context.At(NetworkBatch146150Context.Tls()))).Matched);
    }

    [Fact] public async Task ECH_Only_In_Process_Name_Is_Not_A_Parser_Indicator()
    {
        var r = NetworkBatch146150Context.Tls(); r.ProcessName = "encrypted client hello tester";
        Assert.False((await new R147_EncryptedClienthelloOrEchIndicatorRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Udp_And_Quic_Are_Not_TlsTcp_Context()
    {
        var r = NetworkBatch146150Context.Tls(); r.Info = "encrypted client hello"; r.IsQuic = true;
        Assert.False((await new R147_EncryptedClienthelloOrEchIndicatorRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Plain_Tcp_With_Info_Text_Does_Not_Qualify()
    {
        var r = NetworkBatch146150Context.Tls();
        r.Info = "encrypted client hello"; r.Protocol = "TCP"; r.ApplicationProtocol = "TCP"; r.ApplicationService = "TCP";
        Assert.False((await new R147_EncryptedClienthelloOrEchIndicatorRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Contradictory_Http_Request_Fields_Are_Rejected()
    {
        var r = NetworkBatch146150Context.Tls(); r.Info = "encrypted client hello"; r.HttpMethod = "GET";
        Assert.False((await new R147_EncryptedClienthelloOrEchIndicatorRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public void Default_Shadow_And_Minimum_Confidence_Are_Unchanged()
    {
        var p = new R147_EncryptedClienthelloOrEchIndicatorRule().PrecisionProfile;
        Assert.Equal(60, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
