// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R154AdvancedAccuracyBatchTests
{
    [Fact] public async Task Five_Independent_Explicit_Graphql_Batch_Posts_Trigger()
    {
        var rule = new R154_GraphqlBatchingAbuseRule();
        RuleEvaluationResult? last = null;
        for(int i=0;i<5;i++)
        {
            var r = NetworkBatch151155Context.Http("/graphql", "POST");
            r.Info = $"graphql batch [{{\"operationName\":\"User{i}\"}}]";
            last = await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10));
        }
        Assert.True(last!.Matched); Assert.Equal("R154", Assert.Single(last.Events).RuleId);
    }

    [Fact] public async Task Packet_Replay_Does_Not_Fill_Burst_Threshold()
    {
        var rule = new R154_GraphqlBatchingAbuseRule();
        var id = NetworkBatch151155Context.Http().Id;
        for(int i=0;i<5;i++)
        {
            var r = NetworkBatch151155Context.Http("/graphql","POST");
            r.Info = "graphql batch [{\"operationName\":\"Viewer\"}]"; r.Id=id;
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
    }

    [Fact] public async Task Different_Source_Does_Not_Complete_Window()
    {
        var rule = new R154_GraphqlBatchingAbuseRule();
        for(int i=0;i<4;i++)
        {
            var r = NetworkBatch151155Context.Http("/graphql","POST"); r.Info="graphql batch [{\"operationName\":\"Viewer\"}]";
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
        var other=NetworkBatch151155Context.Http("/graphql","POST"); other.Info="graphql batch [{\"operationName\":\"Viewer\"}]";
        other.Source="203.0.113.154";
        Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(other,50))).Matched);
    }

    [Fact] public async Task Generic_OperationName_Does_Not_Prove_Batching()
    {
        var r=NetworkBatch151155Context.Http("/graphql","POST"); r.Info="graphql operationName Viewer";
        Assert.False((await new R154_GraphqlBatchingAbuseRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Graphql_Batch_Label_On_A_Get_Does_Not_Qualify()
    {
        var r=NetworkBatch151155Context.Http("/graphql","GET"); r.Info="graphql batch [{\"query\":\"viewer\"}]";
        Assert.False((await new R154_GraphqlBatchingAbuseRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Graphql_Text_On_A_Random_Api_Path_Is_Not_Batching()
    {
        var r=NetworkBatch151155Context.Http("/api/users","POST"); r.Info="graphql batch [{\"query\":\"viewer\"}]";
        Assert.False((await new R154_GraphqlBatchingAbuseRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Contradictory_Udp_Transport_Is_Rejected()
    {
        var r=NetworkBatch151155Context.Http("/graphql","POST"); r.IsTcp=false; r.IsUdp=true;
        r.Info="graphql batch [{\"query\":\"viewer\"}]";
        Assert.False((await new R154_GraphqlBatchingAbuseRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public void Existing_Threshold_Floor_And_Shadow_Are_Preserved()
    {
        var p=new R154_GraphqlBatchingAbuseRule().PrecisionProfile;
        Assert.Equal(5,p.Threshold);
        Assert.Equal(72,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
