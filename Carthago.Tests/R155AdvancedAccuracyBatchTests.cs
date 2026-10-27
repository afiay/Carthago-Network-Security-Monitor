// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R155AdvancedAccuracyBatchTests
{
    [Fact] public async Task Six_Distinct_Api_Resource_Paths_Reach_Threshold()
    {
        var rule = new R155_RestApiEnumerationBurstRule();
        RuleEvaluationResult? last = null;
        for(int i=0;i<6;i++)
            last=await rule.EvaluateAsync(NetworkBatch151155Context.At(
                NetworkBatch151155Context.Http($"/api/v1/users/{i}"),i*10));
        Assert.True(last!.Matched); Assert.Equal("R155",Assert.Single(last.Events).RuleId);
    }

    [Fact] public async Task Replayed_Record_Id_Cannot_Fill_Enumeration()
    {
        var rule=new R155_RestApiEnumerationBurstRule();
        var id=NetworkBatch151155Context.Http().Id;
        for(int i=0;i<7;i++)
        {
            var r=NetworkBatch151155Context.Http($"/api/v1/users/{i}");r.Id=id;
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
    }

    [Fact] public async Task Many_Query_Values_On_One_Path_Are_Not_Distinct_Resources()
    {
        var rule=new R155_RestApiEnumerationBurstRule();
        for(int i=0;i<8;i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(
                NetworkBatch151155Context.Http($"/api/v1/users?page={i}&token=PRIVATE"),i*10))).Matched);
    }

    [Fact] public async Task Outbound_Browser_Api_Browsing_Remains_Benign()
    {
        var rule=new R155_RestApiEnumerationBurstRule();
        for(int i=0;i<7;i++)
        {
            var r=NetworkBatch151155Context.Http($"/api/v1/users/{i}");
            r.Source="10.155.0.10";r.Destination="198.51.100.155";
            r.HttpUserAgent="Mozilla/5.0 Chrome/124";
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
    }

    [Fact] public async Task Same_Network_Boundary_Does_Not_Qualify()
    {
        var rule=new R155_RestApiEnumerationBurstRule();
        for(int i=0;i<7;i++)
        {
            var r=NetworkBatch151155Context.Http($"/api/v1/users/{i}");r.Source="10.155.0.10";
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
    }

    [Fact] public async Task Different_Destinations_Cannot_Merge_Enumeration()
    {
        var rule=new R155_RestApiEnumerationBurstRule();
        for(int i=0;i<6;i++)
        {
            var r=NetworkBatch151155Context.Http($"/api/v1/users/{i}");
            r.Destination=i%2==0?"10.155.0.20":"10.155.0.21";
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
    }

    [Fact] public async Task Post_Is_Not_Get_Head_Options_Enumeration()
    {
        var r=NetworkBatch151155Context.Http("/api/v1/users/2","POST");
        Assert.False((await new R155_RestApiEnumerationBurstRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Path_Evidence_Redacts_Sensitive_Resource_And_Policy_Is_Unchanged()
    {
        var rule=new R155_RestApiEnumerationBurstRule();
        RuleEvaluationResult? result=null;
        for(int i=0;i<6;i++)
            result=await rule.EvaluateAsync(NetworkBatch151155Context.At(
                NetworkBatch151155Context.Http($"/api/v1/users/SECRETUSER{i}"),i*10));
        Assert.True(result!.Matched);
        Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,
            x=>x.Key=="http.path" && x.Value.Contains("SECRETUSER",StringComparison.Ordinal));
        Assert.Equal(6,rule.PrecisionProfile.Threshold);
        Assert.Equal(72,rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,rule.PrecisionProfile.DefaultMode);
    }
}
