// SPDX-License-Identifier: MIT
using Carthago.Cli;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class NativeCaptureQualificationTests
{
    [Theory]
    [InlineData("0")]
    [InlineData("61")]
    [InlineData("-1")]
    [InlineData("1.5")]
    public void InvalidDurationRejected(string duration)
        =>Assert.False(NativeCaptureQualification.TryParse(new[]{"capture","qualify","--interface","eth0",
            "--seconds",duration,"--authorized-test-time"},out _));

    [Fact]
    public void ExplicitAuthorizationRequired()
    {
        Assert.False(NativeCaptureQualification.TryParse(new[]{"capture","qualify","--interface","eth0","--seconds","5"},out _));
        Assert.True(NativeCaptureQualification.TryParse(new[]{"capture","qualify","--interface","eth0","--seconds","5","--authorized-test-time"},out var o));
        Assert.Equal(5,o!.Seconds);Assert.Equal("eth0",o.InterfaceId);
    }

    [Fact]
    public async Task MissingAuthorizationFailsBeforeNativeAccess()
    {
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(2,await CliApplication.RunAsync(new[]{"capture","qualify","--interface","eth0","--seconds","5","--json"},output,error));
        Assert.Empty(output.ToString());
    }

    private sealed class Api:NativePcapCaptureSource.IApi
    {
        internal bool FailOpen;
        internal int Code=-2;
        internal int Opened;
        public int Open(string id){Opened++;if(FailOpen)throw new InvalidOperationException();return 101;}
        public int Next(out PortableCaptureFrame? frame){frame=null;return Code;}
        public void Close(){}
        public void Dispose(){}
    }

    [Fact]
    public async Task UnexpectedEofIsFailedSampleNotQualification()
    {
        var api=new Api();
        var r=await NativeCaptureQualification.RunAsync(new("eth0",5),default,id=>new(id,()=>api));
        Assert.Equal("failed",r.Status);Assert.Equal("unexpected_end_of_source",r.Failure);
        Assert.Equal(0L,r.Pipeline.Captured);
        Assert.Equal("unavailable",r.Driver.Status);
    }

    [Fact]
    public async Task StartupFailureNotQualified()
    {
        var api=new Api{FailOpen=true};
        var r=await NativeCaptureQualification.RunAsync(new("eth0",5),default,id=>new(id,()=>api));
        Assert.Equal("failed",r.Status);Assert.Equal("startup_failed",r.Failure);
        Assert.Null(r.Monitor);Assert.Equal("not_attempted",r.Driver.Status);
    }

    [Fact]
    public async Task PreCancelledNeverOpens()
    {
        var api=new Api();using var cancel=new CancellationTokenSource();cancel.Cancel();
        var r=await NativeCaptureQualification.RunAsync(new("eth0",5),cancel.Token,id=>new(id,()=>api));
        Assert.Equal("cancelled",r.Status);Assert.Equal(0,api.Opened);
    }

    [Fact]
    public async Task QuietSourceDeadlineIsInconclusive()
    {
        var api=new Api{Code=0};
        var r=await NativeCaptureQualification.RunAsync(new("eth0",1),default,id=>new(id,()=>api)).WaitAsync(TimeSpan.FromSeconds(5));
        Assert.Equal("inconclusive_no_parsed_frames",r.Status);
        Assert.Equal(0L,r.Pipeline.Captured);Assert.Equal(1,api.Opened);
    }
}
