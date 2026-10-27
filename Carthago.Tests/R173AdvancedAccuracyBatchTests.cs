// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R173AdvancedAccuracyBatchTests
{
    private static TrafficRecord Preflight()
    {
        var r=NetworkBatch166175Context.Http("/admin/api/users","OPTIONS");
        r.HttpRequestHeaders+="\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: authorization,x-api-key\r\nOrigin: https://evil.example";
        return r;
    }
    [Fact] public async Task Cross_Origin_Sensitive_Admin_Preflight_Qualifies()
    {
        Assert.True((await new R173_SuspiciousCorsPreflightToAdminApiRule().EvaluateAsync(NetworkBatch166175Context.At(Preflight()))).Matched);
    }
    [Fact] public async Task Same_Origin_Preflight_Is_Benign()
    {
        var r=Preflight();r.HttpRequestHeaders=r.HttpRequestHeaders!.Replace("https://evil.example","https://web.internal.local");Assert.False((await new R173_SuspiciousCorsPreflightToAdminApiRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Public_Api_Path_Is_Not_Admin_Probe()
    {
        var r=Preflight();r.HttpUri="/api/public/users";Assert.False((await new R173_SuspiciousCorsPreflightToAdminApiRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Missing_Preflight_Method_Is_Not_Cors_Proof()
    {
        var r=Preflight();r.HttpRequestHeaders=r.HttpRequestHeaders!.Replace("Access-Control-Request-Method: POST","X-Note: POST");Assert.False((await new R173_SuspiciousCorsPreflightToAdminApiRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task NonSensitive_Requested_Headers_Are_Not_Enough()
    {
        var r=Preflight();r.HttpRequestHeaders=r.HttpRequestHeaders!.Replace("authorization,x-api-key","content-type,accept");Assert.False((await new R173_SuspiciousCorsPreflightToAdminApiRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Is_Not_Preflight()
    {
        var r=Preflight();r.IsTcp=false;r.IsUdp=true;Assert.False((await new R173_SuspiciousCorsPreflightToAdminApiRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Preflight_Id_Is_Ignored()
    {
        var r=Preflight();var rule=new R173_SuspiciousCorsPreflightToAdminApiRule();Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task Origin_Value_And_Query_Secrets_Are_Redacted()
    {
        var r=Preflight();r.HttpUri="/admin/api/users?token=SECRET173";r.HttpRequestHeaders=r.HttpRequestHeaders!.Replace("evil.example","SECRET173.example");var x=await new R173_SuspiciousCorsPreflightToAdminApiRule().EvaluateAsync(NetworkBatch166175Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET173",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R173_SuspiciousCorsPreflightToAdminApiRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
