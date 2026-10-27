// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R177AdvancedAccuracyBatchTests
{
    private static TrafficRecord Upload()
    {
        var r=NetworkBatch176185Context.Http();
        r.HttpRequestHeaders+="\r\nContent-Type: multipart/form-data; boundary=abc\r\nContent-Disposition: form-data; name=\\"file\\"; filename=\\"shell.php\\"";
        return r;
    }
    [Fact] public async Task Multipart_Executable_Filename_Qualifies()
    {
        var r=Upload();Assert.True((await new R177_HighRiskFileUploadExtensionRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Benign_Png_Upload_Suppressed()
    {
        var r=Upload();r.HttpRequestHeaders=r.HttpRequestHeaders!.Replace("shell.php","image.png");Assert.False((await new R177_HighRiskFileUploadExtensionRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Only_Executable_Name_Not_Proof()
    {
        var r=NetworkBatch176185Context.Http("/upload");r.HttpRequestHeaders+="\r\nContent-Type: multipart/form-data; boundary=abc";r.Info="filename=shell.php";Assert.False((await new R177_HighRiskFileUploadExtensionRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Get_Download_Is_Not_Upload()
    {
        var r=Upload();r.HttpMethod="GET";Assert.False((await new R177_HighRiskFileUploadExtensionRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Udp_Transport_Rejected()
    {
        var r=Upload();r.IsTcp=false;r.IsUdp=true;Assert.False((await new R177_HighRiskFileUploadExtensionRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Put_Executable_Target_Qualifies()
    {
        var r=NetworkBatch176185Context.Http("/upload/app.jsp","PUT");r.HttpRequestHeaders+="\r\nContent-Type: application/octet-stream";Assert.True((await new R177_HighRiskFileUploadExtensionRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Id_Not_Counted_Twice()
    {
        var r=Upload();var rule=new R177_HighRiskFileUploadExtensionRule();Assert.True((await rule.EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,1))).Matched);
    }
    [Fact] public async Task Filename_And_Query_Secret_Redacted()
    {
        var r=Upload();r.HttpUri="/upload?token=SECRET177";r.HttpRequestHeaders=r.HttpRequestHeaders!.Replace("shell.php","SECRET177.php");var x=await new R177_HighRiskFileUploadExtensionRule().EvaluateAsync(NetworkBatch176185Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET177",StringComparison.Ordinal));
    }
    [Fact] public void Default_Mode_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R177_HighRiskFileUploadExtensionRule().PrecisionProfile;
        Assert.Equal(80,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
