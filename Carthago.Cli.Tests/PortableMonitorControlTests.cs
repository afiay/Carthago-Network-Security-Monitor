// SPDX-License-Identifier: MIT
using System.IO.Pipes;
using Carthago.Cli;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableMonitorControlTests
{
    private static string[] RunArgs(params string[] extra)=>new[]{"monitor","run","--interface","eth0","--rules","R589","--authorized-test-time"}.Concat(extra).ToArray();

    [Fact]
    public void ControlAndStopAreIndependentOptIns()
    {
        Assert.True(PortableMonitorCommand.TryParse(RunArgs(),out var a));
        Assert.False(a!.EnableControl);Assert.False(a.AllowStop);
        Assert.False(PortableMonitorCommand.TryParse(RunArgs("--allow-portable-stop"),out _));
        Assert.True(PortableMonitorCommand.TryParse(RunArgs("--enable-portable-control"),out var b));
        Assert.True(b!.EnableControl);Assert.False(b.AllowStop);
        Assert.True(PortableMonitorCommand.TryParse(RunArgs("--enable-portable-control","--allow-portable-stop"),out var c));
        Assert.True(c!.AllowStop);
    }

    [Theory]
    [InlineData("portable-status")]
    [InlineData("portable-health")]
    [InlineData("portable-stop")]
    public void ExactNonemptySessionRequired(string action)
    {
        var id=Guid.NewGuid();
        Assert.True(PortableMonitorControl.TryParse(new[]{"monitor",action,"--session",id.ToString("D")},out var actual,out _));
        Assert.Equal(id,actual);
        Assert.False(PortableMonitorControl.TryParse(new[]{"monitor",action,"--session",Guid.Empty.ToString("D")},out _,out _));
        Assert.False(PortableMonitorControl.TryParse(new[]{"monitor",action,"--session",id.ToString("N")},out _,out _));
        Assert.False(PortableMonitorControl.TryParse(new[]{"monitor",action},out _,out _));
    }

    private static PortableBufferedCaptureRun.Progress Progress()
    {
        var monitor=new PortableMonitorSession(101,new[]{"R589"});
        var queue=new PortableFrameQueue(1,1024);
        return new(monitor.ReadSnapshot,queue.ReadCounters);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task SameUserSessionStatusHealthAndStopPolicy(bool allowStop)
    {
        var id=Guid.NewGuid();using var stop=new CancellationTokenSource();using var serverStop=new CancellationTokenSource();
        var failed=false;
        var server=PortableMonitorControl.ServeAsync(PortableMonitorControl.CreateServer(id),id,Progress(),allowStop,
            stop.Token,()=>stop.Cancel(),serverStop.Token,()=>failed=true);
        try
        {
            var status=await PortableMonitorControl.QueryAsync(id,PortableMonitorControl.Operation.Status,default);
            Assert.Equal("running",status.Status);Assert.Equal(allowStop,status.StopAllowed);Assert.Null(status.Monitor);
            var health=await PortableMonitorControl.QueryAsync(id,PortableMonitorControl.Operation.Health,default);
            Assert.Equal("running",health.Status);Assert.NotNull(health.Monitor);Assert.NotNull(health.Pipeline);
            Assert.Equal("not_assessed",health.SourceHealth);
            var reply=await PortableMonitorControl.QueryAsync(id,PortableMonitorControl.Operation.Stop,default);
            Assert.Equal(allowStop?"stop_accepted":"stop_denied",reply.Status);
            if(allowStop)
            {
                // The acknowledgement is written before cancellation.
                var next=await PortableMonitorControl.QueryAsync(id,PortableMonitorControl.Operation.Status,default);
                Assert.Equal("stopping",next.Status);
            }
            Assert.Equal(allowStop,stop.IsCancellationRequested);
        }
        finally{serverStop.Cancel();await server.WaitAsync(TimeSpan.FromSeconds(5));}
        Assert.False(failed);
    }

    [Fact]
    public async Task StaleSessionDoesNotReachAnotherMonitor()
    {
        var id=Guid.NewGuid();using var serverStop=new CancellationTokenSource();
        var server=PortableMonitorControl.ServeAsync(PortableMonitorControl.CreateServer(id),id,Progress(),true,
            default,()=>throw new InvalidOperationException(),serverStop.Token,()=>{});
        try
        {
            var reply=await PortableMonitorControl.QueryAsync(Guid.NewGuid(),PortableMonitorControl.Operation.Stop,default);
            Assert.Equal("unavailable",reply.Status);
            Assert.Equal("running",(await PortableMonitorControl.QueryAsync(id,PortableMonitorControl.Operation.Status,default)).Status);
        }
        finally{serverStop.Cancel();await server.WaitAsync(TimeSpan.FromSeconds(5));}
    }

    [Fact]
    public async Task PartialMalformedClientIsDisconnectedAndServerRecovers()
    {
        var id=Guid.NewGuid();using var serverStop=new CancellationTokenSource();
        var server=PortableMonitorControl.ServeAsync(PortableMonitorControl.CreateServer(id),id,Progress(),false,
            default,()=>throw new InvalidOperationException(),serverStop.Token,()=>{});
        try
        {
            using(var client=new NamedPipeClientStream(".","carthago-portable-"+id.ToString("N"),
                PipeDirection.InOut,PipeOptions.Asynchronous|PipeOptions.CurrentUserOnly))
            {
                using var timeout=new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await client.ConnectAsync(timeout.Token);
                await client.WriteAsync(new byte[]{1}.AsMemory(),timeout.Token);
            }
            Assert.Equal("running",(await PortableMonitorControl.QueryAsync(id,PortableMonitorControl.Operation.Status,default)).Status);
        }
        finally{serverStop.Cancel();await server.WaitAsync(TimeSpan.FromSeconds(5));}
    }

    [Fact]
    public async Task InvalidCliControlArgumentsFailBeforeConnection()
    {
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(2,await CliApplication.RunAsync(new[]{"monitor","portable-stop","--session","invalid","--json"},output,error));
        Assert.Empty(output.ToString());
    }

    [Fact]
    public async Task CancelledClientDoesNotConnect()
    {
        using var token=new CancellationTokenSource();token.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(()=>PortableMonitorControl.QueryAsync(Guid.NewGuid(),
            PortableMonitorControl.Operation.Status,token.Token));
    }
}
