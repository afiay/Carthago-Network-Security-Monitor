// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Carthago.Cli;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableMonitorCommandTests
{
    private static string[] Args(params string[] extra)=>new[]{"monitor","run","--interface","eth0","--rules","R589","--authorized-test-time"}.Concat(extra).ToArray();

    [Fact]
    public void ParsesExplicitConfigurationAndDefaults()
    {
        Assert.True(PortableMonitorCommand.TryParse(Args(),out var defaults));
        Assert.Equal(5,defaults!.StatusSeconds);Assert.Equal(256,defaults.MaxPackets);Assert.Equal(16777216L,defaults.MaxBytes);
        Assert.True(PortableMonitorCommand.TryParse(Args("--status-seconds","1","--max-packets","16","--max-bytes","4096"),out var o));
        Assert.Equal("eth0",o!.InterfaceId);Assert.Equal(new[]{"R589"},o.Rules);
        Assert.Equal(1,o.StatusSeconds);Assert.Equal(16,o.MaxPackets);Assert.Equal(4096L,o.MaxBytes);
    }

    [Theory]
    [InlineData("--status-seconds","0")]
    [InlineData("--status-seconds","61")]
    [InlineData("--max-packets","4097")]
    [InlineData("--max-bytes","67108865")]
    [InlineData("--rules","R587")]
    [InlineData("--unknown","1")]
    public void RejectsInvalidOrDuplicateOptions(string key,string value)
        =>Assert.False(PortableMonitorCommand.TryParse(Args(key,value),out _));

    [Theory]
    [InlineData("R1000")]
    [InlineData("R589,R589")]
    [InlineData("r589")]
    [InlineData("R589, R587")]
    public void RejectsUnsupportedOrNoncanonicalRules(string ids)
        =>Assert.False(PortableMonitorCommand.TryParse(new[]{"monitor","run","--interface","eth0","--rules",ids,"--authorized-test-time"},out _));

    [Fact]
    public async Task MissingAuthorizationFailsBeforeNativeAccess()
    {
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(2,await CliApplication.RunAsync(new[]{"monitor","run","--interface","eth0","--rules","R589","--json"},output,error));
        Assert.Empty(output.ToString());
    }

    private sealed class Api:NativePcapCaptureSource.IApi
    {
        internal bool FailOpen,End;
        internal int Opens,Reads,Closes,Disposals;
        public int Open(string id){Opens++;if(FailOpen)throw new InvalidOperationException();return 101;}
        public int Next(out PortableCaptureFrame? frame)
        {
            frame=null;
            if(End)return -2;
            if(Reads++!=0)return 0;
            var payload=Encoding.ASCII.GetBytes("GET /config/keystore/test.jsp?secret=private HTTP/1.1\r\nHost: example.test\r\n\r\n");
            var b=new byte[40+payload.Length];b[0]=0x45;b[8]=64;b[9]=6;
            new byte[]{192,0,2,1,198,51,100,2}.CopyTo(b,12);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2),(ushort)b.Length);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20),51000);
            BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22),7001);
            b[32]=0x50;b[33]=0x18;payload.CopyTo(b,40);
            frame=new(b,(uint)b.Length,DateTime.UnixEpoch);return 1;
        }
        public void Close()=>Closes++;
        public void Dispose()=>Disposals++;
    }
    private sealed class Writer:StringWriter
    {
        internal readonly TaskCompletionSource<bool> Health=new(TaskCreationOptions.RunContinuationsAsynchronously);
        internal readonly TaskCompletionSource<bool> Finding=new(TaskCreationOptions.RunContinuationsAsynchronously);
        public override void WriteLine(string? value)
        {
            base.WriteLine(value);
            if(value?.Contains("\"eventType\":\"health\"",StringComparison.Ordinal)==true)Health.TrySetResult(true);
            if(value?.Contains("\"eventType\":\"finding\"",StringComparison.Ordinal)==true)Finding.TrySetResult(true);
        }
    }

    [Fact]
    public async Task ForegroundEmitsStartedFindingHealthAndFinalWithoutRawUri()
    {
        Assert.True(PortableMonitorCommand.TryParse(Args(),out var options));
        var api=new Api();using var output=new Writer();using var cancel=new CancellationTokenSource();
        var run=PortableMonitorCommand.RunAsync(options!,output,true,cancel.Token,id=>new(id,()=>api),TimeSpan.FromMilliseconds(20));
        try
        {
            await Task.WhenAll(output.Health.Task,output.Finding.Task).WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
            Assert.Equal(130,await run.WaitAsync(TimeSpan.FromSeconds(5)));
            Assert.Equal(1,api.Closes);Assert.Equal(1,api.Disposals);
            var lines=output.ToString().Split(Environment.NewLine,StringSplitOptions.RemoveEmptyEntries);
            var rows=lines.Select(line=>JsonDocument.Parse(line)).ToArray();
            try
            {
                Assert.Equal("started",rows[0].RootElement.GetProperty("eventType").GetString());
                Assert.Equal("stopped",rows[^1].RootElement.GetProperty("eventType").GetString());
                Assert.Equal("cancelled",rows[^1].RootElement.GetProperty("data").GetProperty("status").GetString());
                var session=rows[0].RootElement.GetProperty("sessionId").GetString();
                Assert.All(rows,r=>Assert.Equal(session,r.RootElement.GetProperty("sessionId").GetString()));
                Assert.DoesNotContain("secret",output.ToString());Assert.DoesNotContain("192.0.2.1",output.ToString());
                Assert.Equal(1L,rows[^1].RootElement.GetProperty("data").GetProperty("pipeline").GetProperty("processed").GetInt64());
            }
            finally{foreach(var row in rows)row.Dispose();}
        }
        finally{cancel.Cancel();}
    }

    [Theory]
    [InlineData(true,"startup_failed")]
    [InlineData(false,"unexpected_end_of_source")]
    public async Task FailedSourceReturnsFinalFailureAndNoFalseReadiness(bool failOpen,string failure)
    {
        Assert.True(PortableMonitorCommand.TryParse(Args(),out var options));
        var api=new Api{FailOpen=failOpen,End=true};using var output=new StringWriter();
        Assert.Equal(3,await PortableMonitorCommand.RunAsync(options!,output,true,default,id=>new(id,()=>api)));
        Assert.Contains(failure,output.ToString());
        if(failOpen)Assert.DoesNotContain("\"eventType\":\"started\"",output.ToString());
        Assert.Equal(1,api.Closes);Assert.Equal(1,api.Disposals);
    }

    private sealed class Temp:IDisposable
    {
        internal string Root=Path.Combine(Path.GetTempPath(),"carthago-journal-integration-"+Guid.NewGuid().ToString("N"));
        internal Temp()=>Directory.CreateDirectory(Root);
        public void Dispose()=>Directory.Delete(Root,true);
    }

    [Fact]
    public async Task ForegroundJournalMatchesConsoleAndRetainsFinalRecord()
    {
        using var temp=new Temp();using var output=new Writer();using var cancel=new CancellationTokenSource();
        Assert.True(PortableMonitorCommand.TryParse(Args("--journal-directory",temp.Root),out var options));
        var api=new Api();
        var run=PortableMonitorCommand.RunAsync(options!,output,true,cancel.Token,id=>new(id,()=>api),TimeSpan.FromMilliseconds(20));
        try
        {
            await Task.WhenAll(output.Health.Task,output.Finding.Task).WaitAsync(TimeSpan.FromSeconds(5));
            cancel.Cancel();
            Assert.Equal(130,await run.WaitAsync(TimeSpan.FromSeconds(5)));
            var dir=Directory.GetDirectories(temp.Root).Single();
            var persisted=Directory.GetFiles(dir).OrderBy(p=>p,StringComparer.Ordinal).SelectMany(File.ReadAllLines).ToArray();
            Assert.Equal(output.ToString().Split(Environment.NewLine,StringSplitOptions.RemoveEmptyEntries),persisted);
            var summary=PortableMonitorJournal.Inspect(dir,10,default);
            Assert.Equal("shutdown_recorded",summary.Status);Assert.Equal(1L,summary.FindingCount);
            Assert.Equal("R589",Assert.Single(summary.Findings).RuleId);
            Assert.DoesNotContain("secret",string.Join("\n",persisted));
            using var final=JsonDocument.Parse(persisted[^1]);
            Assert.Equal("recorded",final.RootElement.GetProperty("data").GetProperty("journalStatus").GetString());
        }
        finally{cancel.Cancel();}
    }

    private sealed class BrokenJournal:IPortableMonitorJournal
    {
        internal int Appends,Closes,FailAt;
        internal bool FailClose;
        public void Append(string line){if(++Appends==FailAt)throw new IOException("private disk error");}
        public void Dispose(){Closes++;if(FailClose)throw new IOException("private close error");}
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    public async Task JournalFailureStopsCaptureAndDoesNotRetry(int failAt)
    {
        using var output=new StringWriter();using var cancel=new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var journal=new BrokenJournal{FailAt=failAt};
        Assert.True(PortableMonitorCommand.TryParse(Args("--journal-directory","unused"),out var options));
        var api=new Api();
        var code=await PortableMonitorCommand.RunAsync(options!,output,true,cancel.Token,id=>new(id,()=>api),
            TimeSpan.FromSeconds(60),(_,_)=>journal).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(3,code);Assert.Equal(failAt,journal.Appends);Assert.Equal(1,journal.Closes);
        Assert.Equal(1,api.Closes);Assert.Equal(1,api.Disposals);
        var lines=output.ToString().Split(Environment.NewLine,StringSplitOptions.RemoveEmptyEntries);
        using var final=JsonDocument.Parse(lines[^1]);
        Assert.Equal("stopped",final.RootElement.GetProperty("eventType").GetString());
        Assert.Equal("journal_failed",final.RootElement.GetProperty("data").GetProperty("failure").GetString());
        Assert.Equal("failed",final.RootElement.GetProperty("data").GetProperty("journalStatus").GetString());
        Assert.DoesNotContain("private disk error",output.ToString());
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task FinalAppendOrCloseFailureStillReportsFinalConsoleFailure(bool closeFailure)
    {
        using var output=new StringWriter();
        var journal=new BrokenJournal{FailAt=closeFailure?0:2,FailClose=closeFailure};
        Assert.True(PortableMonitorCommand.TryParse(Args("--journal-directory","unused"),out var options));
        var api=new Api{End=true};
        Assert.Equal(3,await PortableMonitorCommand.RunAsync(options!,output,true,default,id=>new(id,()=>api),
            createJournal:(_,_)=>journal));
        Assert.Equal(2,journal.Appends);Assert.Equal(1,journal.Closes);
        Assert.Equal(1,api.Closes);Assert.Contains("journal_failed",output.ToString());
        Assert.DoesNotContain("private close error",output.ToString());
    }

    [Fact]
    public async Task JournalProvisionFailurePrecedesCaptureSourceCreation()
    {
        using var output=new StringWriter();
        Assert.True(PortableMonitorCommand.TryParse(Args("--journal-directory","unused"),out var options));
        await Assert.ThrowsAsync<IOException>(()=>PortableMonitorCommand.RunAsync(options!,output,true,default,
            _=>throw new InvalidOperationException("source must not be created"),createJournal:(_,_)=>throw new IOException()));
        Assert.Empty(output.ToString());
    }

}
