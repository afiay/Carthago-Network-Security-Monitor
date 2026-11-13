// SPDX-License-Identifier: MIT
using Carthago.Services.Flow;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableFlowStateTests
{
    private static readonly DateTime Epoch = new(2026,1,1,0,0,0,DateTimeKind.Utc);
    private static FlowKey Key(int port=51000)=>new("192.0.2.1",port,"198.51.100.1",443,"TCP");
    private static byte[] Hello()=>new byte[]{0x16,3,3,0,5,1,0,0,1,0x42};

    [Fact]
    public void FlowTypesArePortableAndDirectionIsReversible()
    {
        var key=Key();
        Assert.Equal(key,key.Reverse().Reverse());
        Assert.NotEqual(key,key.Reverse());
        Assert.Equal(key.GetHashCode(),Key().GetHashCode());
        Assert.Equal("Carthago.Core",typeof(FlowKey).Assembly.GetName().Name);
        Assert.Same(typeof(FlowKey).Assembly,typeof(HandshakeBufferState).Assembly);
        Assert.Same(typeof(FlowKey).Assembly,typeof(LatencyTrackerState).Assembly);
    }

    [Fact]
    public void HandshakeSessionsDoNotShareIdenticalFiveTuple()
    {
        var a=new HandshakeBufferState(()=>Epoch);
        var b=new HandshakeBufferState(()=>Epoch);
        var wire=Hello();var key=Key();
        a.AddClientBytes(key,wire.AsSpan(0,5));
        Assert.True(a.TryGetClientHello(key).IsEmpty);
        a.AddClientBytes(key,wire.AsSpan(5));
        Assert.Equal(wire,a.TryGetClientHello(key).ToArray());
        Assert.True(b.TryGetClientHello(key).IsEmpty);
        b.AddClientBytes(key,wire);
        a.Clear();
        Assert.True(a.TryGetClientHello(key).IsEmpty);
        Assert.Equal(wire,b.TryGetClientHello(key).ToArray());
    }

    [Fact]
    public void HandshakeExpiryUsesInjectedClock()
    {
        var now=Epoch;
        var state=new HandshakeBufferState(()=>now);
        state.AddClientBytes(Key(),Hello());
        now=Epoch.AddSeconds(119);
        Assert.False(state.TryGetClientHello(Key()).IsEmpty);
        now=Epoch.AddSeconds(120);
        Assert.True(state.TryGetClientHello(Key()).IsEmpty);
        Assert.Equal(0,state.ActiveFlowCount);
        Assert.Equal(1L,state.ExpiredFlowCount);
    }

    [Fact]
    public void HandshakeRejectsOversizeAndRemovesBothDirections()
    {
        var state=new HandshakeBufferState(()=>Epoch);
        var bytes=new byte[32769];bytes[0]=0x16;
        state.AddClientBytes(Key(),bytes);
        Assert.Equal(1L,state.RejectedSegmentCount);
        state.AddClientBytes(Key(),Hello());
        Assert.True(state.TryGetClientHello(Key()).IsEmpty);
        state.AddClientBytes(Key().Reverse(),Hello());
        Assert.Equal(2,state.ActiveFlowCount);
        state.Remove(Key());
        Assert.Equal(0,state.ActiveFlowCount);
    }

    [Fact]
    public void HandshakeCapacityIsBounded()
    {
        var state=new HandshakeBufferState(()=>Epoch);
        for(int i=0;i<1025;i++)state.AddClientBytes(Key(10000+i),Hello());
        Assert.Equal(1024,state.ActiveFlowCount);
        Assert.Equal(1L,state.EvictedFlowCount);
    }

    [Fact]
    public void LatencySessionsKeepIdenticalKeysIndependent()
    {
        var a=new LatencyTrackerState();var b=new LatencyTrackerState();
        a.NoteSyn(Key(),Epoch);
        a.NoteSynAck(Key(),Epoch.AddMilliseconds(4));
        a.NoteFirstDataServer(Key(),Epoch.AddMilliseconds(16));
        a.NoteFirstDataServer(Key(),Epoch.AddMilliseconds(50));
        Assert.Equal(("rtt:1-5;ttfb:10-20","rtt:1-5;ttfb:10-20"),a.GetLatencyFingerprints(Key()));
        Assert.Equal(("",""),b.GetLatencyFingerprints(Key()));
        b.NoteSyn(Key(),Epoch);
        Assert.Equal(("rtt:na;ttfb:na","rtt:na;ttfb:na"),b.GetLatencyFingerprints(Key()));
        a.Clear();
        Assert.Equal(("",""),a.GetLatencyFingerprints(Key()));
        Assert.Equal(1,b.ActiveFlowCount);
    }

    [Fact]
    public void LatencyCapacityEvictsOldestInsertionAndStaysBounded()
    {
        var state=new LatencyTrackerState();
        for(int i=0;i<=LatencyTrackerState.MaxFlows;i++)state.NoteSyn(Key(i+1),Epoch);
        Assert.Equal(LatencyTrackerState.MaxFlows,state.ActiveFlowCount);
        Assert.Equal(("",""),state.GetLatencyFingerprints(Key(1)));
        Assert.NotEqual(("",""),state.GetLatencyFingerprints(Key(LatencyTrackerState.MaxFlows+1)));
    }
}
