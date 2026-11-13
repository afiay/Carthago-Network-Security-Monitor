// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text.Json;
using Carthago.Cli;
using Carthago.Services;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortablePcapInspectionTests
{
    private static void U16(byte[] b,int p,ushort n,bool little)
    { if(little)BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(p),n);else BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(p),n); }
    private static void U32(byte[] b,int p,uint n,bool little)
    { if(little)BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(p),n);else BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(p),n); }
    private static byte[] Header(bool little,bool nano,uint link=101)
    {
        var h=new byte[24];U32(h,0,nano?0xa1b23c4du:0xa1b2c3d4u,little);
        U16(h,4,2,little);U16(h,6,4,little);U32(h,16,65535,little);U32(h,20,link,little);return h;
    }
    private static byte[] Record(byte[] data,bool little,uint seconds=1700000000,uint fraction=123456,uint? original=null)
    {
        var h=new byte[16];U32(h,0,seconds,little);U32(h,4,fraction,little);
        U32(h,8,(uint)data.Length,little);U32(h,12,original??(uint)data.Length,little);
        return h.Concat(data).ToArray();
    }
    private static byte[] Udp()=>new byte[]{0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,1,198,51,100,2,0xc3,0x50,0xd4,0x31,0,8,0,0};

    [Theory]
    [InlineData(true,false)]
    [InlineData(false,false)]
    [InlineData(true,true)]
    [InlineData(false,true)]
    public async Task ReaderSupportsByteOrdersAndTimestampPrecisions(bool little,bool nano)
    {
        uint fraction=nano?123456789u:123456u;
        using var stream=new MemoryStream(Header(little,nano).Concat(Record(Udp(),little,fraction:fraction)).ToArray());
        var reader=await PortablePcapReader.OpenAsync(stream,default);
        var packet=(await reader.ReadAsync(default))!.Value;
        Assert.Equal(101,reader.LinkLayerType);
        Assert.Equal(nano?"nanoseconds":"microseconds",reader.TimestampResolution);
        Assert.Equal(nano?123456789u:123456000u,packet.Nanoseconds);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1700000000).UtcDateTime.AddTicks(packet.Nanoseconds/100),packet.TimestampUtc);
        Assert.Equal(Udp(),packet.Data);Assert.Null(await reader.ReadAsync(default));
    }

    [Theory]
    [InlineData("magic")]
    [InlineData("version")]
    [InlineData("snap")]
    [InlineData("link")]
    public async Task InvalidGlobalHeaderFailsClosed(string variant)
    {
        var h=Header(true,false);
        switch(variant){case "magic":h[0]=0;break;case "version":h[4]=3;break;
            case "snap":U32(h,16,0,true);break;case "link":U32(h,20,999,true);break;}
        using var stream=new MemoryStream(h);
        await Assert.ThrowsAsync<InvalidDataException>(()=>PortablePcapReader.OpenAsync(stream,default));
    }

    [Theory]
    [InlineData("fraction")]
    [InlineData("original")]
    [InlineData("snap")]
    public async Task InvalidPacketRecordFailsBeforeAllocation(string variant)
    {
        var r=Record(Udp(),true);
        switch(variant){case "fraction":U32(r,4,1000000,true);break;case "original":U32(r,12,27,true);break;
            case "snap":U32(r,8,65536,true);U32(r,12,65536,true);break;}
        using var stream=new MemoryStream(Header(true,false).Concat(r).ToArray());
        var reader=await PortablePcapReader.OpenAsync(stream,default);
        await Assert.ThrowsAsync<InvalidDataException>(()=>reader.ReadAsync(default));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(15)]
    [InlineData(17)]
    public async Task PartialRecordIsNotCleanEof(int bytes)
    {
        using var stream=new MemoryStream(Header(true,false).Concat(Record(Udp(),true).Take(bytes)).ToArray());
        var reader=await PortablePcapReader.OpenAsync(stream,default);
        await Assert.ThrowsAsync<EndOfStreamException>(()=>reader.ReadAsync(default));
    }

    [Fact]
    public async Task CommandReturnsBoundedUntrustedProjectionAndFullCounts()
    {
        string path=Path.Combine(Path.GetTempPath(),Guid.NewGuid()+".pcap");
        try
        {
            await File.WriteAllBytesAsync(path,Header(true,false).Concat(Record(Udp(),true))
                .Concat(Record(Udp(),true,seconds:1699999999))
                .Concat(Record(Udp(),true,original:40))
                .Concat(Record(new byte[]{0},true)).ToArray());
            using var output=new StringWriter();using var error=new StringWriter();
            Assert.Equal(0,await CliApplication.RunAsync(new[]{"pcap","inspect",path,"--limit","1","--json"},output,error));
            using var json=JsonDocument.Parse(output.ToString());var root=json.RootElement;
            Assert.Equal("untrusted_capture",root.GetProperty("provenance").GetString());
            Assert.Equal("not_assessed",root.GetProperty("detectionValidation").GetString());
            var c=root.GetProperty("capture");
            Assert.Equal(4,c.GetProperty("packetsRead").GetInt32());
            Assert.Equal(2,c.GetProperty("parsed").GetInt32());
            Assert.Equal(1,c.GetProperty("rejected").GetInt32());
            Assert.Equal(1,c.GetProperty("captureTruncated").GetInt32());
            Assert.Equal(1,c.GetProperty("clockResets").GetInt32());
            var rows=c.GetProperty("rows");Assert.Equal(1,rows.GetArrayLength());
            Assert.Equal("192.0.2.1",rows[0].GetProperty("source").GetString());
            Assert.Equal("UDP",rows[0].GetProperty("protocol").GetString());
            Assert.False(rows[0].TryGetProperty("info",out _));
            Assert.False(rows[0].TryGetProperty("httpRequestHeaders",out _));
            Assert.Equal("",error.ToString());
        }
        finally{File.Delete(path);}
    }

    [Fact]
    public async Task BigEndianNullCaptureNormalizesAddressFamilyForCore()
    {
        string path=Path.Combine(Path.GetTempPath(),Guid.NewGuid()+".pcap");
        try
        {
            var frame=new byte[]{0,0,0,2}.Concat(Udp()).ToArray();
            await File.WriteAllBytesAsync(path,Header(false,false,0).Concat(Record(frame,false)).ToArray());
            using var output=new StringWriter();using var error=new StringWriter();
            Assert.Equal(0,await CliApplication.RunAsync(new[]{"pcap","inspect",path,"--json"},output,error));
            using var json=JsonDocument.Parse(output.ToString());
            Assert.Equal(1,json.RootElement.GetProperty("capture").GetProperty("parsed").GetInt32());
        }
        finally{File.Delete(path);}
    }

    [Fact]
    public async Task MalformedFileDoesNotEmitPartialSuccessJson()
    {
        string path=Path.Combine(Path.GetTempPath(),Guid.NewGuid()+".pcap");
        try
        {
            await File.WriteAllBytesAsync(path,Header(true,false).Concat(Record(Udp(),true)).Concat(new byte[]{1}).ToArray());
            using var output=new StringWriter();using var error=new StringWriter();
            Assert.Equal(3,await CliApplication.RunAsync(new[]{"pcap","inspect",path,"--json"},output,error));
            Assert.Equal("",output.ToString());Assert.DoesNotContain(path,error.ToString());
        }
        finally{File.Delete(path);}
    }

    [Theory]
    [InlineData("0")]
    [InlineData("101")]
    [InlineData("x")]
    public async Task InvalidSampleLimitReturnsUsage(string limit)
    {
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(2,await CliApplication.RunAsync(new[]{"pcap","inspect","fixture.pcap","--limit",limit,"--json"},output,error));
    }
}
