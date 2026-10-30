// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Request burst is not verified artifact transfer.
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R358AdvancedAccuracyBatchTests
{
    private static Task<RuleEvaluationResult> Eval(Carthago.Models.TrafficRecord r, int second = 0)
        => new R358_BambooBuildArtifactBulkDownloadRule().EvaluateAsync(NetworkBatch356360Context.At(r, second)).AsTask();

    [Fact] public async Task Fifth_Parsed_Artifact_Get_Is_Eligible_After_Four_Below_Threshold()
    {
        var r = NetworkBatch356360Context.Http("bamboo-" + Guid.NewGuid().ToString("N") + ".internal",
            "/browse/PROJ-PLAN-1/artifact/shared/build.zip");
        for (var i = 0; i < 4; i++)
        {
            var result = await Eval(r, i);
            Assert.False(result.Matched);
            Assert.Contains(result.NoMatchReasons, x => x.Code == "WINDOW_THRESHOLD_NOT_MET");
        }
        var fifth = await Eval(r, 4);
        Assert.True(fifth.Matched);
        Assert.Equal("R358", Assert.Single(fifth.Events).RuleId);
    }

    [Fact] public async Task Four_Requests_Alone_Do_Not_Meet_Existing_Burst_Threshold()
    {
        var r = NetworkBatch356360Context.Http("bamboo-" + Guid.NewGuid().ToString("N") + ".internal",
            "/artifact/build.zip");
        for (var i = 0; i < 4; i++)
            Assert.False((await Eval(r, i)).Matched);
    }

    [Theory]
    [InlineData("/browse/PROJ-PLAN-1")]
    [InlineData("/artifact/")]
    [InlineData("/artifacts/build.zip")]
    [InlineData("/download/build.zip")]
    public async Task Non_Artifact_Or_Incomplete_Path_Does_Not_Count(string path)
    {
        var r = NetworkBatch356360Context.Http("bamboo.internal", path);
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "BAMBOO_ARTIFACT_PATH_NOT_OBSERVED");
    }

    [Fact] public async Task Post_To_Artifact_Is_Not_A_Download_Request()
    {
        var r = NetworkBatch356360Context.Http("bamboo.internal", "/artifact/build.zip", "POST");
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "BAMBOO_DOWNLOAD_METHOD_REQUIRED");
    }

    [Fact] public async Task Tls_Only_Is_Not_Parsed_Http()
    {
        var r = NetworkBatch356360Context.Http("bamboo.internal", "/artifact/build.zip");
        r.ApplicationProtocol = "TLS";
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "BAMBOO_HTTP_REQUEST_MISSING");
    }

    [Fact] public async Task Absolute_Target_Is_Not_Trusted()
    {
        var r = NetworkBatch356360Context.Http("bamboo.internal", "http://bamboo.internal/artifact/build.zip");
        Assert.Contains((await Eval(r)).NoMatchReasons, x => x.Code == "BAMBOO_TARGET_UNTRUSTED");
    }

    [Fact] public async Task Fifth_Event_Does_Not_Expose_Query_Secret()
    {
        var r = NetworkBatch356360Context.Http("bamboo-" + Guid.NewGuid().ToString("N") + ".internal",
            "/artifact/build.zip?auth=synthetic-private");
        for (var i = 0; i < 4; i++) await Eval(r, i);
        var result = await Eval(r, 4);
        Assert.True(result.Matched);
        Assert.DoesNotContain("synthetic-private", Assert.Single(result.Events).Evidence ?? string.Empty);
    }

    [Fact] public void Original_Burst_Threshold_Mode_And_Confidence_Are_Preserved()
    {
        var p = new R358_BambooBuildArtifactBulkDownloadRule().PrecisionProfile;
        Assert.Equal(5, p.Threshold);
        Assert.Equal(74, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
