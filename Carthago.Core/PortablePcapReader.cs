// SPDX-License-Identifier: MIT
using System.Buffers.Binary;

namespace Carthago.Services;

/// <summary>Strict, bounded classic-PCAP reader; no native capture dependency.</summary>
internal sealed class PortablePcapReader
{
    internal const int MaxFrameBytes = 1_048_576;
    internal const long MaxFileBytes = 512L * 1024 * 1024;
    internal const int MaxPackets = 1_000_000;
    private readonly Stream _stream;
    private readonly bool _little;
    private readonly bool _nano;
    private readonly uint _snaplen;
    private long _bytes = 24;
    private int _packets;
    internal int LinkLayerType { get; }
    internal bool IsLittleEndian => _little;
    internal string TimestampResolution => _nano ? "nanoseconds" : "microseconds";
    internal readonly record struct Packet(DateTime TimestampUtc, uint Nanoseconds, uint OriginalLength, byte[] Data);

    private PortablePcapReader(Stream stream,bool little,bool nano,uint snaplen,int link)
    { _stream=stream; _little=little; _nano=nano; _snaplen=snaplen; LinkLayerType=link; }

    internal static async Task<PortablePcapReader> OpenAsync(Stream stream,CancellationToken token)
    {
        var header=new byte[24];
        await stream.ReadExactlyAsync(header.AsMemory(),token);
        uint magic=BinaryPrimitives.ReadUInt32BigEndian(header);
        bool little=magic is 0xd4c3b2a1 or 0x4d3cb2a1;
        bool nano=magic is 0xa1b23c4d or 0x4d3cb2a1;
        if(magic is not (0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1))
            throw new InvalidDataException("Unsupported capture format.");
        if(U16(header,4,little)!=2 || U16(header,6,little)!=4)
            throw new InvalidDataException("Unsupported PCAP version.");
        uint snap=U32(header,16,little), link=U32(header,20,little);
        if(snap==0 || snap>MaxFrameBytes || link is not (0 or 1 or 12 or 101 or 113 or 228 or 229 or 276))
            throw new InvalidDataException("Unsupported PCAP snaplen or link type.");
        return new PortablePcapReader(stream,little,nano,snap,(int)link);
    }

    internal async Task<Packet?> ReadAsync(CancellationToken token)
    {
        var header=new byte[16];
        int first=await _stream.ReadAsync(header.AsMemory(0,1),token);
        if(first==0)return null;
        await _stream.ReadExactlyAsync(header.AsMemory(1),token);
        uint seconds=U32(header,0,_little), fraction=U32(header,4,_little);
        uint captured=U32(header,8,_little), original=U32(header,12,_little);
        if(fraction>=(_nano?1_000_000_000u:1_000_000u) || captured>_snaplen ||
            captured>original || captured>MaxFrameBytes || ++_packets>MaxPackets ||
            _bytes+16+captured>MaxFileBytes)
            throw new InvalidDataException("Invalid or excessive PCAP packet record.");
        _bytes+=16+captured;
        var data=new byte[(int)captured];
        await _stream.ReadExactlyAsync(data.AsMemory(),token);
        uint nanos=_nano?fraction:fraction*1000;
        var utc=DateTimeOffset.FromUnixTimeSeconds(seconds).UtcDateTime.AddTicks(nanos/100);
        return new Packet(utc,nanos,original,data);
    }

    private static ushort U16(byte[] bytes,int at,bool little)=>little?
        BinaryPrimitives.ReadUInt16LittleEndian(bytes.AsSpan(at,2)):
        BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(at,2));
    private static uint U32(byte[] bytes,int at,bool little)=>little?
        BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(at,4)):
        BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(at,4));
}
