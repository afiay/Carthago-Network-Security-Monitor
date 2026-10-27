// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R153AdvancedAccuracyBatchTests
{
    [Fact] public async Task Cross_Boundary_Graphql_Introspection_Query_Matches()
    {
        var r = NetworkBatch151155Context.Http("/graphql?query=query{__schema{types{name}}}");
        var v = await new R153_GraphqlIntrospectionQueryRule().EvaluateAsync(NetworkBatch151155Context.At(r));
        Assert.True(v.Matched); Assert.Equal("R153", Assert.Single(v.Events).RuleId);
    }

    [Fact] public async Task Ordinary_Graphql_Query_Remains_Benign()
    {
        var r = NetworkBatch151155Context.Http("/graphql?query=query{viewer{id}}");
        Assert.False((await new R153_GraphqlIntrospectionQueryRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Introspection_Keyword_In_Packet_Info_Does_Not_Imply_Query()
    {
        var r = NetworkBatch151155Context.Http("/graphql"); r.Info = "__schema introspection";
        Assert.False((await new R153_GraphqlIntrospectionQueryRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Introspection_Token_Only_In_Path_Does_Not_Imply_Query()
    {
        var r = NetworkBatch151155Context.Http("/graphql/__schema");
        Assert.False((await new R153_GraphqlIntrospectionQueryRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Internal_To_Internal_Traffic_Is_Out_Of_Scope()
    {
        var r = NetworkBatch151155Context.Http("/graphql?query=__schema"); r.Source = "10.153.0.12";
        Assert.False((await new R153_GraphqlIntrospectionQueryRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Missing_Tcp_Flag_Cannot_Qualify()
    {
        var r = NetworkBatch151155Context.Http("/graphql?query=__schema"); r.IsTcp = false;
        Assert.False((await new R153_GraphqlIntrospectionQueryRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Raw_Query_Secrets_Do_Not_Appear_As_Http_Path_Evidence()
    {
        var r = NetworkBatch151155Context.Http("/graphql?query=__schema&token=SENSITIVE_CANARY_153");
        var v = await new R153_GraphqlIntrospectionQueryRule().EvaluateAsync(NetworkBatch151155Context.At(r));
        Assert.True(v.Matched);
        var e = Assert.Single(v.Events);
        Assert.DoesNotContain(e.StructuredEvidence!.Items, x => x.Key == "http.path" && x.Value.Contains("SENSITIVE_CANARY", StringComparison.Ordinal));
    }

    [Fact] public void Existing_Shadow_And_Confidence_Floor_Remain()
    {
        var p = new R153_GraphqlIntrospectionQueryRule().PrecisionProfile;
        Assert.Equal(72, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
