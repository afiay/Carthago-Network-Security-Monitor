// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text.Json;
using Carthago.Cli;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortablePcapNgTests
{
    private static void W16(byte[] b,int p,ushort v,bool le)
    {if(le)BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(p),v);else BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(p),v);}
    private static void W32(byte[] b,int p,uint v,bool le)
    {if(le)BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p),v);else BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(p),v);}
    private static void W64(byte[] b,int p,ulong v,bool le)
    {if(le)BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(p),v);else BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(p),v);}
    private static byte[] Block(uint type,byte[] body,bool le)
    {
        var b=new byte[12+body.Length];W32(b,0,type,le);W32(b,4,(uint)b.Length,le);
        body.CopyTo(b,8);W32(b,b.Length-4,(uint)b.Length,le);return b;
    }
    private static byte[] Section(bool le)
    {
        var b=new byte[16];W32(b,0,0x1a2b3c4d,le);W16(b,4,1,le);W64(b,8,ulong.MaxValue,le);
        return Block(0x0a0d0d0a,b,le);
    }
    private static byte[] Interface(bool le,ushort link=101,byte? resolution=null,long? offset=null)
    {
        var b=new byte[8];W16(b,0,link,le);W32(b,4,65535,le);
        var options=new List<byte>();
        if(resolution.HasValue){var o=new byte[8];W16(o,0,9,le);W16(o,2,1,le);o[4]=resolution.Value;options.AddRange(o);}
        if(offset.HasValue){var o=new byte[12];W16(o,0,14,le);W16(o,2,8,le);W64(o,4,unchecked((ulong)offset.Value),le);options.AddRange(o);}
        if(options.Count>0)options.AddRange(new byte[4]);
        return Block(1,b.Concat(options).ToArray(),le);
    }
    private static byte[] Udp(byte[]? payload=null,int sport=51000,int dport=54321,bool reverse=false)
    {
        payload??=Array.Empty<byte>();var b=new byte[28+payload.Length];
        b[0]=0x45;b[8]=64;b[9]=17;W16(b,2,(ushort)b.Length,false);
        byte[] a={192,0,2,1},z={198,51,100,2};(reverse?z:a).CopyTo(b,12);(reverse?a:z).CopyTo(b,16);
        W16(b,20,(ushort)sport,false);W16(b,22,(ushort)dport,false);W16(b,24,(ushort)(8+payload.Length),false);payload.CopyTo(b,28);return b;
    }
    private static byte[] Packet(bool le,uint id,ulong timestamp,byte[] data,uint? original=null)
    {
        var b=new byte[20+((data.Length+3)&~3)];W32(b,0,id,le);W32(b,4,(uint)(timestamp>>32),le);W32(b,8,(uint)timestamp,le);
        W32(b,12,(uint)data.Length,le);W32(b,16,original??(uint)data.Length,le);data.CopyTo(b,20);return Block(6,b,le);
    }
    private static MemoryStream Capture(params byte[][] blocks)=>new(blocks.SelectMany(x=>x).ToArray());

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task MultipleInterfacesHaveIndependentTimestampSettings(bool le)
    {
        using var stream=Capture(Section(le),Interface(le),Interface(le,1,0x8a,-1),
            Packet(le,0,1_500_000,Udp()),Packet(le,1,1536,new byte[14].Concat(Udp()).ToArray()));
        var r=new PortablePcapNgReader(stream);
        var a=(await r.ReadAsync(default))!.Value;var b=(await r.ReadAsync(default))!.Value;
        Assert.Equal(DateTime.UnixEpoch.AddMilliseconds(1500),a.TimestampUtc);
        Assert.Equal(DateTime.UnixEpoch.AddMilliseconds(500),b.TimestampUtc);
        Assert.Equal(500_000_000u,b.Nanoseconds);Assert.Equal(1,b.LinkLayerType);
        Assert.Equal(1,b.InterfaceId);Assert.Null(await r.ReadAsync(default));
        Assert.Equal(2,r.InterfaceCount);
    }

    [Fact]
    public async Task SectionChangesByteOrderAndResetsInterfaceIds()
    {
        using var stream=Capture(Section(true),Interface(true),Packet(true,0,1,Udp()),
            Section(false),Interface(false,101,9),Packet(false,0,123456789,Udp()));
        var r=new PortablePcapNgReader(stream);
        Assert.Equal(0,(await r.ReadAsync(default))!.Value.Section);
        var p=(await r.ReadAsync(default))!.Value;
        Assert.Equal(1,p.Section);Assert.Equal(0,p.InterfaceId);Assert.False(p.LittleEndian);
        Assert.Equal(123456789u,p.Nanoseconds);Assert.Null(await r.ReadAsync(default));
    }

    [Theory]
    [InlineData("trailer")]
    [InlineData("interface")]
    [InlineData("length")]
    [InlineData("unsupported")]
    public async Task MalformedOrUnsupportedBlocksFailClosed(string variant)
    {
        var p=Packet(true,0,1,Udp());
        switch(variant){case "trailer":p[^1]=1;break;case "interface":W32(p,8,1,true);break;
            case "length":W32(p,20,100,true);break;case "unsupported":W32(p,0,3,true);break;}
        using var stream=Capture(Section(true),Interface(true),p);
        await Assert.ThrowsAsync<InvalidDataException>(()=>new PortablePcapNgReader(stream).ReadAsync(default));
    }

    [Fact]
    public async Task CommandIsolatesInterfacesAndCountsTruncation()
    {
        string path=Path.Combine(Path.GetTempPath(),Guid.NewGuid()+".pcapng");
        try
        {
            byte[] rrq={0,1,0x66,0,0x6f,0x63,0x74,0x65,0x74,0};
            byte[] reply={0,3,0,1,0x41};
            using var stream=Capture(Section(true),Interface(true),Interface(true),
                Packet(true,0,1_000_000,Udp(rrq,51000,69)),
                Packet(true,1,2_000_000,Udp(reply,52000,51000,true)),
                Packet(true,0,2_000_000,Udp(reply,52000,51000,true)),
                Packet(true,0,3_000_000,Udp(),40));
            await File.WriteAllBytesAsync(path,stream.ToArray());
            using var output=new StringWriter();using var error=new StringWriter();
            Assert.Equal(0,await CliApplication.RunAsync(new[]{"pcap","inspect",path,"--json"},output,error));
            using var json=JsonDocument.Parse(output.ToString());var c=json.RootElement.GetProperty("capture");
            Assert.Equal("pcapng",c.GetProperty("format").GetString());
            Assert.Equal(4,c.GetProperty("packetsRead").GetInt32());Assert.Equal(3,c.GetProperty("parsed").GetInt32());
            Assert.Equal(1,c.GetProperty("captureTruncated").GetInt32());
            var rows=c.GetProperty("rows");
            Assert.NotEqual("tftp.data.first",rows[1].GetProperty("applicationProtocol").GetString());
            Assert.Equal("tftp.data.first",rows[2].GetProperty("applicationProtocol").GetString());
            Assert.Equal(1,rows[1].GetProperty("interfaceId").GetInt32());
        }
        finally{File.Delete(path);}
    }

    [Fact]
    public async Task FiniteSectionLengthMustMatchItsBlockEnvelope()
    {
        var idb=Interface(true);
        var packet=Packet(true,0,1,Udp());
        var section=Section(true);
        W64(section,16,(ulong)(idb.Length+packet.Length),true);
        using var valid=Capture(section,idb,packet);
        var reader=new PortablePcapNgReader(valid);
        Assert.NotNull(await reader.ReadAsync(default));
        Assert.Null(await reader.ReadAsync(default));
        W64(section,16,(ulong)(idb.Length+packet.Length+4),true);
        using var invalid=Capture(section,idb,packet);
        reader=new PortablePcapNgReader(invalid);
        Assert.NotNull(await reader.ReadAsync(default));
        await Assert.ThrowsAsync<InvalidDataException>(()=>reader.ReadAsync(default));
    }

    [Fact]
    public async Task UnknownMetadataBlockIsSkippedButIncompleteBlockFails()
    {
        using var stream=Capture(Section(true),Block(0x12345678,new byte[4],true),Interface(true),Packet(true,0,1,Udp()));
        Assert.NotNull(await new PortablePcapNgReader(stream).ReadAsync(default));
        using var bad=Capture(Section(true),Interface(true),Packet(true,0,1,Udp())[..^1]);
        await Assert.ThrowsAsync<EndOfStreamException>(()=>new PortablePcapNgReader(bad).ReadAsync(default));
    }
}
