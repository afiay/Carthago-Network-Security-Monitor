// SPDX-License-Identifier: MIT
using System.Buffers.Binary;

namespace Carthago.Services;

/// <summary>Bounded PCAPNG 1.0 section/interface/enhanced-packet reader.</summary>
internal sealed class PortablePcapNgReader
{
    internal const int MaxInterfaces=8;
    private const int MaxBlockBytes=PortablePcapReader.MaxFrameBytes+65536;
    private const int MaxSections=64;
    private const int MaxBlocks=2_000_000;
    private readonly Stream _stream;
    private bool _little;
    private long _bytes;
    private long? _sectionEnd;
    private int _section=-1,_blocks,_packets;
    private readonly List<Interface> _interfaces=new();
    private sealed record Interface(int Link,uint Snap,ulong Units,long Offset);
    internal readonly record struct Packet(int Section,int InterfaceId,int LinkLayerType,bool LittleEndian,
        DateTime TimestampUtc,uint Nanoseconds,ulong RawTimestamp,uint OriginalLength,byte[] Data);
    internal int SectionCount=>_section+1;
    internal int InterfaceCount {get;private set;}
    internal PortablePcapNgReader(Stream stream)=>_stream=stream;

    internal async Task<Packet?> ReadAsync(CancellationToken token)
    {
        while(true)
        {
            token.ThrowIfCancellationRequested();
            var prefix=new byte[12];
            if(await _stream.ReadAsync(prefix.AsMemory(0,1),token)==0)
            {
                if(_section<0 || (_sectionEnd.HasValue && _bytes!=_sectionEnd.Value))
                    throw new InvalidDataException("Incomplete PCAPNG section.");
                return null;
            }
            await _stream.ReadExactlyAsync(prefix.AsMemory(1,7),token);
            bool shb=BinaryPrimitives.ReadUInt32BigEndian(prefix)==0x0a0d0d0a;
            int prefixLength=8;
            if(shb)
            {
                if(_sectionEnd.HasValue && _bytes!=_sectionEnd.Value)
                    throw new InvalidDataException("Section length mismatch.");
                await _stream.ReadExactlyAsync(prefix.AsMemory(8,4),token);
                uint bom=BinaryPrimitives.ReadUInt32BigEndian(prefix.AsSpan(8));
                if(bom is not (0x1a2b3c4d or 0x4d3c2b1a))throw new InvalidDataException("Invalid byte order.");
                _little=bom==0x4d3c2b1a;prefixLength=12;
            }
            else if(_section<0)throw new InvalidDataException("Missing section header.");
            uint length=U32(prefix,4);
            if(length<(shb?28u:12u) || length%4!=0 || length>MaxBlockBytes ||
                ++_blocks>MaxBlocks || _bytes+length>PortablePcapReader.MaxFileBytes ||
                (!shb && _sectionEnd.HasValue && _bytes+length>_sectionEnd.Value))
                throw new InvalidDataException("Invalid PCAPNG block length.");
            var block=new byte[(int)length];prefix.AsSpan(0,prefixLength).CopyTo(block);
            await _stream.ReadExactlyAsync(block.AsMemory(prefixLength),token);
            if(U32(block,block.Length-4)!=length)throw new InvalidDataException("Mismatched block trailer.");
            _bytes+=length;
            var packet=Process(block,shb);
            if(packet.HasValue)return packet;
        }
    }

    private Packet? Process(byte[] b,bool shb)
    {
        int end=b.Length-4;
        if(shb)
        {
            if(++_section>=MaxSections || U16(b,12)!=1 || U16(b,14)!=0)
                throw new InvalidDataException("Unsupported section version or count.");
            long declared=unchecked((long)U64(b,16));
            if(declared < -1 || declared>PortablePcapReader.MaxFileBytes-_bytes)
                throw new InvalidDataException("Invalid section length.");
            _sectionEnd=declared==-1?null:_bytes+declared;
            _interfaces.Clear();Options(b,24,end,null);
            return null;
        }
        uint type=U32(b,0);
        if(type==1)
        {
            if(end<16 || _interfaces.Count>=MaxInterfaces || U16(b,10)!=0)
                throw new InvalidDataException("Invalid interface description.");
            int link=U16(b,8);uint snap=U32(b,12);
            if(link is not (0 or 1 or 12 or 101 or 113 or 228 or 229 or 276) || snap>PortablePcapReader.MaxFrameBytes)
                throw new InvalidDataException("Unsupported interface.");
            ulong units=1_000_000;long offset=0;bool seenResolution=false,seenOffset=false;
            Options(b,16,end,(code,at,len)=>{
                if(code==9)
                {
                    if(seenResolution || len!=1)throw new InvalidDataException("Invalid resolution.");
                    seenResolution=true;int exponent=b[at]&127;
                    if((b[at]&128)!=0)
                    {
                        if(exponent>63)throw new InvalidDataException("Unsupported binary resolution.");
                        units=1UL<<exponent;
                    }
                    else
                    {
                        if(exponent>19)throw new InvalidDataException("Unsupported decimal resolution.");
                        units=1;for(int i=0;i<exponent;i++)units*=10;
                    }
                }
                else if(code==14)
                {
                    if(seenOffset || len!=8)throw new InvalidDataException("Invalid timestamp offset.");
                    seenOffset=true;offset=unchecked((long)U64(b,at));
                }
            });
            _interfaces.Add(new Interface(link,snap,units,offset));InterfaceCount++;
            return null;
        }
        if(type is 2 or 3)throw new InvalidDataException("Unsupported packet block type.");
        if(type!=6)return null; // Unknown/metadata blocks: envelope checked, never interpreted.
        if(end<28 || ++_packets>PortablePcapReader.MaxPackets)throw new InvalidDataException("Invalid packet block.");
        uint id=U32(b,8),captured=U32(b,20),original=U32(b,24);
        if(id>=_interfaces.Count)throw new InvalidDataException("Unknown interface.");
        var iface=_interfaces[(int)id];
        if(captured>original || captured>PortablePcapReader.MaxFrameBytes ||
            (iface.Snap!=0 && captured>iface.Snap))
            throw new InvalidDataException("Invalid captured length.");
        int padded=((int)captured+3)&~3;
        if(padded>end-28)throw new InvalidDataException("Truncated packet block.");
        Options(b,28+padded,end,null);
        ulong raw=((ulong)U32(b,12)<<32)|U32(b,16);
        Int128 seconds=(Int128)(raw/iface.Units)+iface.Offset;
        if(seconds < -62135596800L || seconds>253402300799L)
            throw new InvalidDataException("Timestamp out of range.");
        uint nanos=(uint)(((UInt128)(raw%iface.Units)*1_000_000_000)/iface.Units);
        var utc=DateTimeOffset.FromUnixTimeSeconds((long)seconds).UtcDateTime.AddTicks(nanos/100);
        return new Packet(_section,(int)id,iface.Link,_little,utc,nanos,raw,original,b.AsSpan(28,(int)captured).ToArray());
    }

    private void Options(byte[] b,int at,int end,Action<ushort,int,int>? visit)
    {
        while(at<end)
        {
            if(end-at<4)throw new InvalidDataException("Incomplete option.");
            ushort code=U16(b,at),len=U16(b,at+2);at+=4;
            if(code==0)
            {
                if(len!=0 || at!=end)throw new InvalidDataException("Invalid end option.");
                return;
            }
            int padded=(len+3)&~3;
            if(padded>end-at)throw new InvalidDataException("Invalid option length.");
            visit?.Invoke(code,at,len);at+=padded;
        }
    }
    private ushort U16(byte[] b,int at)=>_little?BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at)):BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(at));
    private uint U32(byte[] b,int at)=>_little?BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at)):BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at));
    private ulong U64(byte[] b,int at)=>_little?BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(at)):BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(at));
}
