// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableMonitorSessionTests
{
    private static readonly DateTime Epoch = DateTime.UnixEpoch.AddHours(1);

    private static byte[] Frame(string path)
    {
        var payload=Encoding.ASCII.GetBytes($"GET {path} HTTP/1.1\r\nHost: example.test\r\n\r\n");
        var b=new byte[40+payload.Length];
        b[0]=0x45;b[8]=64;b[9]=6;
        new byte[]{192,0,2,1,198,51,100,2}.CopyTo(b,12);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2),(ushort)b.Length);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20),51000);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22),7001);
        b[32]=0x50;b[33]=0x18;payload.CopyTo(b,40);return b;
    }

    private static PortableMonitorSession.FrameResult Feed(PortableMonitorSession session,byte[] frame,int seconds=0)
        =>session.Process(frame,(uint)frame.Length,Epoch.AddSeconds(seconds));

    [Fact]
    public void AllFiveDetectorsUseOneFramePipeline()
    {
        var ids=new[]{"R586","R587","R588","R589","R590"};
        var paths=new[]{"/wp-content/plugins/wp2shell_test/file.php","/SetupWizard.aspx/next",
            "/LogoImageHandler.ashx?clazz=example","/config/keystore/test.jsp","/?search=%00{.cmd.exe"};
        var session=new PortableMonitorSession(101,ids);
        for(int i=0;i<ids.Length;i++)
        {
            var result=Feed(session,Frame(paths[i]),i);
            Assert.Equal("parsed",result.Status);
            Assert.Equal((long)i+1,result.PacketNumber);
            Assert.Equal(ids[i],Assert.Single(result.Findings).RuleId);
            Assert.Equal("GET",result.Findings[0].Method);
        }
        Assert.Empty(Feed(session,Frame(paths[0]),5).Findings);
        Assert.Empty(Feed(session,Frame("/LogoImageHandler.ashx?class=example"),6).Findings);
        var s=session.ReadSnapshot();
        Assert.Equal(7L,s.Received);Assert.Equal(7L,s.Parsed);Assert.Equal(5L,s.Matches);Assert.Equal(1L,s.Suppressed);
        Assert.All(s.Rules,r=>{Assert.Equal(7L,r.Evaluated);Assert.Equal(1L,r.Matches);});
        Assert.Equal(1L,s.Rules[0].Suppressed);
        Assert.All(s.Rules.Skip(1),r=>Assert.Equal(0L,r.Suppressed));
    }

    [Fact]
    public void TruncatedAndRejectedFramesDoNotReachDetectors()
    {
        var session=new PortableMonitorSession(101,new[]{"R589"});
        var frame=Frame("/config/keystore/test.jsp");
        Assert.Equal("capture_truncated",session.Process(frame,(uint)frame.Length+1,Epoch).Status);
        Assert.Equal("rejected",Feed(session,new byte[]{0},1).Status);
        var s=session.ReadSnapshot();
        Assert.Equal(2L,s.Received);Assert.Equal(0L,s.Parsed);Assert.Equal(1L,s.Rejected);Assert.Equal(1L,s.CaptureTruncated);
        Assert.Equal(0L,Assert.Single(s.Rules).Evaluated);
        Assert.Single(Feed(session,frame,2).Findings);
    }

    [Fact]
    public void ReversedClockResetsParserAndDetectorEvenOnTruncatedFrame()
    {
        var session=new PortableMonitorSession(101,new[]{"R589"});
        var frame=Frame("/config/keystore/test.jsp");
        Assert.Single(Feed(session,frame,10).Findings);
        Assert.Empty(Feed(session,frame,11).Findings);
        Assert.True(session.Process(frame,(uint)frame.Length+1,Epoch).ClockReset);
        Assert.Single(Feed(session,frame,1).Findings);
        var s=session.ReadSnapshot();
        Assert.Equal(1L,s.ClockResets);Assert.Equal(2L,s.Matches);Assert.Equal(1L,s.Suppressed);
        Assert.Equal(3L,Assert.Single(s.Rules).Evaluated);
    }

    [Fact]
    public void SessionsAndSnapshotsDoNotShareState()
    {
        var ids=new[]{"R589"};
        var a=new PortableMonitorSession(101,ids);var b=new PortableMonitorSession(101,ids);
        ids[0]="R587"; // constructor owns its selection
        var frame=Frame("/config/keystore/test.jsp");
        Assert.Single(Feed(a,frame).Findings);
        var before=a.ReadSnapshot();
        Assert.Single(Feed(b,frame).Findings);
        Assert.Empty(Feed(a,frame,1).Findings);
        Assert.Equal(1L,b.ReadSnapshot().Received);
        Assert.Equal(1L,before.Received);Assert.Equal(0L,before.Suppressed);
        Assert.Equal("R589",Assert.Single(a.ReadSnapshot().Rules).RuleId);
    }

    [Fact]
    public void InvalidMetadataAndCancellationDoNotChangeCounters()
    {
        var session=new PortableMonitorSession(101,new[]{"R589"});
        var frame=Frame("/config/keystore/test.jsp");
        Assert.Throws<ArgumentException>(()=>session.Process(frame,(uint)frame.Length-1,Epoch));
        Assert.Throws<ArgumentException>(()=>session.Process(frame,(uint)frame.Length,DateTime.SpecifyKind(Epoch,DateTimeKind.Unspecified)));
        Assert.Throws<ArgumentException>(()=>session.Process(new byte[PortableMonitorSession.MaxFrameBytes+1],
            (uint)PortableMonitorSession.MaxFrameBytes+1,Epoch));
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(()=>session.Process(frame,(uint)frame.Length,Epoch,cancel.Token));
        Assert.Equal(0L,session.ReadSnapshot().Received);
    }

    [Theory]
    [InlineData("")]
    [InlineData("R1000")]
    [InlineData("R589,R589")]
    [InlineData("r589")]
    public void InvalidSelectionIsRejected(string selection)
        =>Assert.Throws<ArgumentException>(()=>new PortableMonitorSession(101,selection.Split(',')));

    [Fact]
    public void UnsupportedLinkTypeIsRejected()
        =>Assert.Throws<ArgumentOutOfRangeException>(()=>new PortableMonitorSession(999,new[]{"R589"}));
}
