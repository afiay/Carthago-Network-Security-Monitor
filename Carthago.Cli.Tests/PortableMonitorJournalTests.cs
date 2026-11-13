// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Cli;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableMonitorJournalTests
{
    private static string Line(Guid id,long sequence,string type,object data)=>JsonSerializer.Serialize(new
    {schemaVersion=1,mode="portable_foreground",sessionId=id,sequence,eventType=type,detectionValidation="not_assessed",data});
    private static object Finding()=>new {ruleId="R589",method="GET",packetNumber=1,timestampUtc=DateTime.UnixEpoch,secret="never project"};
    private sealed class Temp:IDisposable
    {
        internal string Root=Path.Combine(Path.GetTempPath(),"carthago-journal-"+Guid.NewGuid().ToString("N"));
        internal Temp()=>Directory.CreateDirectory(Root);
        public void Dispose()=>Directory.Delete(Root,true);
    }

    [Fact]
    public void ClosedSessionProjectsOnlyBoundedSanitizedFindings()
    {
        using var temp=new Temp();var id=Guid.NewGuid();string dir;
        using(var journal=new PortableMonitorJournal(temp.Root,id))
        {
            dir=journal.DirectoryPath;journal.Append(Line(id,1,"started",new{}));
            journal.Append(Line(id,2,"finding",Finding()));journal.Append(Line(id,3,"finding",Finding()));
            journal.Append(Line(id,4,"stopped",new{status="stopped"}));
        }
        var s=PortableMonitorJournal.Inspect(dir,1,default);
        Assert.Equal("shutdown_recorded",s.Status);Assert.Equal(4L,s.Records);Assert.Equal(2L,s.FindingCount);
        Assert.Equal(3L,Assert.Single(s.Findings).Sequence);Assert.False(s.RetentionGap);
        Assert.DoesNotContain("secret",JsonSerializer.Serialize(s));
    }

    [Fact]
    public void RotationKeepsOnlyOwnNewestSegmentsAndReportsGap()
    {
        using var temp=new Temp();var id=Guid.NewGuid();string dir;
        var unrelated=Path.Combine(temp.Root,"unrelated.txt");File.WriteAllText(unrelated,"keep");
        using(var journal=new PortableMonitorJournal(temp.Root,id,512,2))
        {
            dir=journal.DirectoryPath;journal.Append(Line(id,1,"started",new{}));
            for(int i=2;i<=10;i++)journal.Append(Line(id,i,"finding",Finding()));
        }
        Assert.Equal(2,Directory.GetFiles(dir).Length);Assert.True(File.Exists(unrelated));
        var s=PortableMonitorJournal.Inspect(dir,100,default);
        Assert.True(s.RetentionGap);Assert.Equal(10L,s.LastSequence);Assert.Equal("shutdown_not_recorded",s.Status);
        Assert.All(Directory.GetFiles(dir),p=>Assert.True(new FileInfo(p).Length<=512));
    }

    [Fact]
    public void PartialFinalRecordIsNotCounted()
    {
        using var temp=new Temp();var id=Guid.NewGuid();string dir;
        using(var journal=new PortableMonitorJournal(temp.Root,id))
        {dir=journal.DirectoryPath;journal.Append(Line(id,1,"started",new{}));}
        File.AppendAllText(Directory.GetFiles(dir).Single(),"{partial");
        var s=PortableMonitorJournal.Inspect(dir,10,default);
        Assert.True(s.PartialTail);Assert.Equal("incomplete_tail",s.Status);Assert.Equal(1L,s.Records);
    }

    [Theory]
    [InlineData("wrong-session")]
    [InlineData("gap")]
    [InlineData("unknown-event")]
    [InlineData("invalid-finding")]
    public void CorruptCompleteRecordFailsClosed(string kind)
    {
        using var temp=new Temp();var id=Guid.NewGuid();string dir;
        using(var journal=new PortableMonitorJournal(temp.Root,id))
        {
            dir=journal.DirectoryPath;journal.Append(Line(id,1,"started",new{}));
            journal.Append(kind switch {
                "wrong-session"=>Line(Guid.NewGuid(),2,"finding",Finding()),
                "gap"=>Line(id,3,"finding",Finding()),
                "unknown-event"=>Line(id,2,"unknown",new{}),
                _=>Line(id,2,"finding",new{ruleId="R1000",method="GET",packetNumber=1,timestampUtc=DateTime.UnixEpoch})
            });
        }
        Assert.Throws<InvalidDataException>(()=>PortableMonitorJournal.Inspect(dir,10,default));
    }

    [Fact]
    public void SessionDirectoryCannotBeReused()
    {
        using var temp=new Temp();var id=Guid.NewGuid();
        using var journal=new PortableMonitorJournal(temp.Root,id);
        Assert.Throws<IOException>(()=>new PortableMonitorJournal(temp.Root,id));
    }

    [Fact]
    public void OversizedRecordRejectedBeforeWriting()
    {
        using var temp=new Temp();using var journal=new PortableMonitorJournal(temp.Root,Guid.NewGuid(),256,2);
        Assert.Throws<InvalidDataException>(()=>journal.Append(new string('x',300)));
        Assert.Empty(Directory.GetFiles(journal.DirectoryPath));
    }

    [Fact]
    public async Task CliInspectionReturnsUntrustedSummary()
    {
        using var temp=new Temp();var id=Guid.NewGuid();string dir;
        using(var journal=new PortableMonitorJournal(temp.Root,id))
        {dir=journal.DirectoryPath;journal.Append(Line(id,1,"stopped",new{status="failed"}));}
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(0,await CliApplication.RunAsync(new[]{"monitor","journal",dir,"--json"},output,error));
        using var json=JsonDocument.Parse(output.ToString());
        Assert.Equal("untrusted_journal",json.RootElement.GetProperty("provenance").GetString());
        Assert.Equal("shutdown_recorded",json.RootElement.GetProperty("journal").GetProperty("status").GetString());
    }

    [Fact]
    public void JournalOptionIsExplicit()
    {
        var args=new[]{"monitor","run","--interface","eth0","--rules","R589","--authorized-test-time"};
        Assert.True(PortableMonitorCommand.TryParse(args,out var a));Assert.Null(a!.JournalDirectory);
        Assert.True(PortableMonitorCommand.TryParse(args.Concat(new[]{"--journal-directory","evidence"}).ToArray(),out var b));
        Assert.Equal("evidence",b!.JournalDirectory);
    }

    [Fact]
    public void FailedAppendLatchesWriterAndDisposeCannotReopen()
    {
        using var temp=new Temp();var journal=new PortableMonitorJournal(temp.Root,Guid.NewGuid(),256,2);
        Assert.Throws<InvalidDataException>(()=>journal.Append(new string('x',300)));
        Assert.Throws<InvalidOperationException>(()=>journal.Append("{}"));
        journal.Dispose();journal.Dispose();
        Assert.Throws<InvalidOperationException>(()=>journal.Append("{}"));
        Assert.Empty(Directory.GetFiles(journal.DirectoryPath));
    }
}
