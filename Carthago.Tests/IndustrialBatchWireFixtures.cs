// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

// Shared independent wire fixtures, compiled into Windows and portable tests.
// No production parser or CRC is used to construct the fixture bytes.
internal static class IndustrialBatchWireFixtures
{
    internal static readonly DateTime Epoch = new(2026,11,13,0,0,0,DateTimeKind.Utc);
    internal static IEnumerable<object[]> PositiveFrames()
    {
        yield return new object[] { IndustrialBatchOperation.BacnetDeviceSystemStatusRead, 47808, false, false, "810A001101040005070C0C020000011970" };
        yield return new object[] { IndustrialBatchOperation.BacnetDeviceSystemStatusRead, 47808, false, false, "810A001101070205FF0C0C023FFFFE1970" };
        yield return new object[] { IndustrialBatchOperation.BacnetDeviceAllPropertiesRead, 47808, false, false, "810A001301040005070E0C020000011E09081F" };
        yield return new object[] { IndustrialBatchOperation.BacnetDeviceAllPropertiesRead, 47808, false, false, "810A001301070205FF0E0C023FFFFE1E09081F" };
        yield return new object[] { IndustrialBatchOperation.BacnetInputOutOfService, 47808, false, false, "810A001401040005070F0C0000000119513E113F" };
        yield return new object[] { IndustrialBatchOperation.BacnetInputOutOfService, 47808, false, false, "810A001401070205FF0F0C00FFFFFE19513E113F" };
        yield return new object[] { IndustrialBatchOperation.BacnetAtomicFileRead, 47808, false, false, "810A0016010400050706C4028000010E31002202000F" };
        yield return new object[] { IndustrialBatchOperation.BacnetAtomicFileRead, 47808, false, false, "810A001601070205FF06C402BFFFFE0E31002202000F" };
        yield return new object[] { IndustrialBatchOperation.BacnetAtomicFileWrite, 47808, false, false, "810A0117010400050707C4028000010E310065FE0100505249564154452D4241434E45542D46494C45131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF0F" };
        yield return new object[] { IndustrialBatchOperation.BacnetAtomicFileWrite, 47808, false, false, "810A011701070205FF07C402BFFFFE0E310065FE0100AFADB6A9BEABBAD2BDBEBCB1BAABD2B9B6B3BAECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A090807060504030201000F" };
        yield return new object[] { IndustrialBatchOperation.FinsCpuStatusRead, 9600, false, true, "800002000100000700000601" };
        yield return new object[] { IndustrialBatchOperation.FinsCpuStatusRead, 9600, false, true, "80000200010000FE00FF0601" };
        yield return new object[] { IndustrialBatchOperation.FinsBulkDataMemoryRead, 9600, false, true, "800002000100000700000101820000000100" };
        yield return new object[] { IndustrialBatchOperation.FinsBulkDataMemoryRead, 9600, false, true, "80000200010000FE00FF0101827F00000100" };
        yield return new object[] { IndustrialBatchOperation.Dnp3IntegrityRead, 20000, false, true, "056414C401000700CE3EC0C0013C01063C02063C03063C04069C09" };
        yield return new object[] { IndustrialBatchOperation.Dnp3IntegrityRead, 20000, false, true, "056414C40000EFFFAAC2FFCF013C04063C02063C01063C03062562" };
        yield return new object[] { IndustrialBatchOperation.Dnp3AbsoluteTimeWrite, 20000, false, true, "056412C4010007001755C0C002320107010000000000003FC1" };
        yield return new object[] { IndustrialBatchOperation.Dnp3AbsoluteTimeWrite, 20000, false, true, "056412C40000EFFF73A9FFCF0232010701FFFFFFFFFFFF5409" };
        yield return new object[] { IndustrialBatchOperation.ModbusReadWriteSamePairZero, 502, true, false, "00010000000F011700000002000000020400000000" };
        yield return new object[] { IndustrialBatchOperation.ModbusReadWriteSamePairZero, 502, true, false, "FFFF0000000FF717FFFE0002FFFE00020400000000" };
        yield return new object[] { IndustrialBatchOperation.ModbusBulkFileWrite, 502, true, false, "0001000000D20115CF060001000000640718293A4B5C6D7E8FA0B1C2D3E4F5061728394A5B6C7D8E9FB0C1D2E3F405162738495A6B7C8D9EAFC0D1E2F30415263748596A7B8C9DAEBFD0E1F2031425364758697A8B9CADBECFE0F102132435465768798A9BACBDCEDFF00112233445566778899AABBCCDDEEF00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0F2031425364758697A8B9CADBECFD0E1F30415263748596A7B8C9DAEBFC0D1E2F405162738495A6B7C8D9EAFB0C1D2E3F5061728394A5B6C7D8E9FA0B1C2D3E" };
        yield return new object[] { IndustrialBatchOperation.ModbusBulkFileWrite, 502, true, false, "FFFF000000FAF715F7060001269800780718293A4B5C6D7E8FA0B1C2D3E4F5061728394A5B6C7D8E9FB0C1D2E3F405162738495A6B7C8D9EAFC0D1E2F30415263748596A7B8C9DAEBFD0E1F2031425364758697A8B9CADBECFE0F102132435465768798A9BACBDCEDFF00112233445566778899AABBCCDDEEF00112233445566778899AABBCCDDEEFF102132435465768798A9BACBDCEDFE0F2031425364758697A8B9CADBECFD0E1F30415263748596A7B8C9DAEBFC0D1E2F405162738495A6B7C8D9EAFB0C1D2E3F5061728394A5B6C7D8E9FA0B1C2D3E4F60718293A4B5C6D7E8F90A1B2C3D4E5F708192A3B4C5D6E7F8091A2B3C4D5E6F8091A2B3C4D5E6" };
        yield return new object[] { IndustrialBatchOperation.SnmpInterfaceAdminDown, 161, false, false, "30340201000411505249564154452D434F4D4D554E495459A31C0201010201000201003011300F060A2B060102010202010701020102" };
        yield return new object[] { IndustrialBatchOperation.SnmpInterfaceAdminDown, 161, false, false, "30390201010411505249564154452D434F4D4D554E495459A3210202008002010002010030153013060E2B060102010202010787FFFFFF7F020102" };
        yield return new object[] { IndustrialBatchOperation.SnmpIpv4ForwardingDisable, 161, false, false, "30320201000411505249564154452D434F4D4D554E495459A31A020101020100020100300F300D06082B06010201040100020102" };
        yield return new object[] { IndustrialBatchOperation.SnmpIpv4ForwardingDisable, 161, false, false, "3081A502010104818261616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161A31B02020080020100020100300F300D06082B06010201040100020102" };
    }
    internal static byte[] Decode(string hex) => Convert.FromHexString(hex);
    private static void U16(byte[] b,int at,ushort v)=>BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(at,2),v);
    private static void U32(byte[] b,int at,uint v)=>BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(at,4),v);
    private static uint Reverse(uint x,int width)
    {
        uint value=0;
        for(int i=0;i<width;i++){value=(value<<1)|(x&1);x>>=1;}
        return value;
    }
    internal static ushort IndependentDnpCrc(ReadOnlySpan<byte> bytes)
    {
        uint value=0;
        foreach(byte b in bytes)
        {
            value ^= Reverse(b,8)<<8;
            for(int i=0;i<8;i++)value=((value<<1)^((value&0x8000)!=0?0x3D65u:0u))&0xFFFF;
        }
        return (ushort)(Reverse(value,16)^0xFFFF);
    }
    internal static byte[] Mutate(string hex,string name,int offset,int value,bool dnp)
    {
        var data=Decode(hex);data[offset]=checked((byte)value);
        // Preserve CRCs for semantic mutations to exercise the semantic guard.
        if(dnp&&!name.StartsWith("crc",StringComparison.Ordinal))
        {
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(8,2),IndependentDnpCrc(data.AsSpan(0,8)));
            BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(data.Length-2,2),
                IndependentDnpCrc(data.AsSpan(10,data.Length-12)));
        }
        return data;
    }
    private static byte[] Frame(byte[] payload,bool tcp,int sourcePort,int destPort,string source,string dest,
        uint seq=101,uint ack=201,byte flags=0x18,string variant="")
    {
        int header=tcp?40:28;
        var raw=new byte[header+payload.Length];raw[0]=0x45;raw[8]=64;raw[9]=tcp?(byte)6:(byte)17;
        U16(raw,2,(ushort)(raw.Length+(variant=="ip-incomplete"?1:0)));
        if(variant=="ip-fragment")U16(raw,6,0x2000);
        IPAddress.Parse(source).GetAddressBytes().CopyTo(raw,12);
        IPAddress.Parse(dest).GetAddressBytes().CopyTo(raw,16);
        U16(raw,20,(ushort)sourcePort);U16(raw,22,(ushort)destPort);
        if(tcp){U32(raw,24,seq);U32(raw,28,ack);raw[32]=0x50;raw[33]=flags;}
        else U16(raw,24,(ushort)(8+payload.Length-(variant=="udp-length"?1:0)));
        payload.CopyTo(raw,header);return raw;
    }
    internal static TrafficRecord? Capture(byte[] data,int port,bool tcp,bool sameSourcePort,
        string variant="",string src="8.8.8.8",string dst="10.1.2.45",
        Func<byte[],int,TrafficRecord?>? parse=null)
    {
        if(parse==null){var processor=new PortablePacketProcessor(()=>Epoch);parse=processor.ParseFrame;}
        if(variant=="private-source")src="10.1.1.10";
        if(variant=="public-destination")dst="9.9.9.9";
        int sport=sameSourcePort?port:51000,dport=variant=="wrong-port"?port+1:port;
        if(variant=="wrong-source-port")sport=sameSourcePort?port+1:port==47808?0:port;
        if(variant=="truncated")data=data[..^1];
        if(variant=="trailing")data=data.Concat(new byte[]{0}).ToArray();
        if(variant=="coalesced")data=data.Concat(data).ToArray();
        if(variant=="empty")data=Array.Empty<byte>();
        if(variant=="wrong-transport")tcp=!tcp;
        if(!tcp)return parse(Frame(data,false,sport,dport,src,dst,variant:variant),12);
        TrafficRecord? Send(byte[] bytes,bool client=true,uint seq=101,uint ack=201,byte flags=0x18,string v="")
            => parse(Frame(bytes,true,client?sport:dport,client?dport:sport,
                client?src:dst,client?dst:src,seq,ack,flags,v),12);
        if(variant!="no-syn")Send(Array.Empty<byte>(),seq:100,ack:0,flags:2);
        if(variant!="no-synack")Send(Array.Empty<byte>(),false,200,variant=="wrong-synack"?100u:101u,0x12);
        if(variant=="response")return Send(data,false,201,101);
        if(variant=="retransmit")Send(data);
        if(variant=="second-payload"){Send(new byte[]{1,2,3,4,5,6,7,8});return Send(data,seq:109);}
        if(variant=="server-first"){Send(new byte[]{1,2,3,4,5,6,7,8},false,201,101);return Send(data,ack:209);}
        if(variant=="fin-before")Send(Array.Empty<byte>(),seq:101,flags:0x11);
        if(variant=="fragmented-payload")
        {
            int n=data.Length/2;Send(data[..n]);return Send(data[n..],seq:101+(uint)n);
        }
        return Send(data,seq:variant=="gap"?102u:101u,ack:variant=="wrong-ack"?200u:201u,
            flags:variant=="non-psh"?(byte)0x10:(byte)0x18,v:variant);
    }
}
