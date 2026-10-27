// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R158AdvancedAccuracyBatchTests
{

    [Fact] public async Task External_Swagger_Json_Probe_Matches()
    {
        Assert.True((await new R158_SwaggerOpenapiExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/swagger.json")))).Matched);
    }
    [Fact] public async Task Swagger_Ui_Subpath_Matches()
    {
        Assert.True((await new R158_SwaggerOpenapiExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/swagger-ui/index.html")))).Matched);
    }
    [Fact] public async Task Public_Swagger_Documentation_Host_Is_Excluded()
    {
        var r=NetworkBatch156165Context.Http("/swagger.json");r.HttpHost="editor.swagger.io";r.HttpRequestHeaders="Host: editor.swagger.io";
        Assert.False((await new R158_SwaggerOpenapiExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Lookalike_Path_Is_Not_An_Endpoint()
    {
        Assert.False((await new R158_SwaggerOpenapiExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/swagger.json.backup")))).Matched);
    }
    [Fact] public async Task Packet_Info_Cannot_Manufacture_Swagger()
    {
        var r=NetworkBatch156165Context.Http("/home");r.Info="GET /swagger.json";
        Assert.False((await new R158_SwaggerOpenapiExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task External_To_External_Does_Not_Cross_Inbound_Boundary()
    {
        var r=NetworkBatch156165Context.Http("/swagger.json");r.Destination="198.51.100.156";
        Assert.False((await new R158_SwaggerOpenapiExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Record_Cannot_Match_Twice()
    {
        var rule=new R158_SwaggerOpenapiExposureProbeRule();var r=NetworkBatch156165Context.Http("/swagger.json");
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,3))).Matched);
    }
    [Fact] public void Configured_Mode_And_Confidence_Floor_Remain_Unchanged()
    {
        var profile=new R158_SwaggerOpenapiExposureProbeRule().PrecisionProfile;
        Assert.Equal(72,profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,profile.DefaultMode);
    }
}
