// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableIndustrialInspectorTests
{
    [Fact]
    public void InspectorsHaveOnePortableOwner()
    {
        var core=typeof(SnmpEnterpriseSetInspector).Assembly;
        Assert.Equal("Carthago.Core",core.GetName().Name);
        foreach(var type in new[]{typeof(BacnetBvlcControlInspector),typeof(BacnetDeviceCommunicationControlInspector),
            typeof(BacnetObjectListReadInspector),typeof(BacnetReinitializeDeviceInspector),typeof(BacnetWritePropertyInspector),
            typeof(Dnp3DisableUnsolicitedInspector),typeof(Dnp3RestartRequestInspector),typeof(Dnp3UnsolicitedBinaryEventInspector),
            typeof(ModbusSingleRegisterWriteInspector),typeof(ModbusClearMaskWriteInspector)})
            Assert.Same(core,type.Assembly);
        Assert.DoesNotContain(core.GetReferencedAssemblies(),a=>a.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    private static byte[] Tlv(byte tag,params byte[][] values)
    {
        var bytes=values.SelectMany(x=>x).ToArray();
        return new[]{tag,(byte)bytes.Length}.Concat(bytes).ToArray();
    }
    private static byte[] I(byte value)=>Tlv(2,new[]{value});
    private static byte[] Snmp(byte pdu=0xa3,byte version=1)
    {
        var binding=Tlv(0x30,Tlv(6,new byte[]{0x2b,6,1,4,1,9,1}),Tlv(4,"fixture"u8.ToArray()));
        return Tlv(0x30,I(version),Tlv(4,"lab"u8.ToArray()),Tlv(pdu,I(7),I(0),I(0),Tlv(0x30,binding)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    public void SnmpEnterpriseSetRecognizesSupportedVersions(int version)
    {
        var wire=Snmp(version:(byte)version);
        Assert.True(SnmpEnterpriseSetInspector.TryInspect(wire));
        for(int n=0;n<wire.Length;n++) Assert.False(SnmpEnterpriseSetInspector.TryInspect(wire.AsSpan(0,n)));
        Assert.False(SnmpEnterpriseSetInspector.TryInspect(wire.Concat(new byte[]{0}).ToArray()));
    }

    [Theory]
    [InlineData(0xa0)]
    [InlineData(0xa1)]
    [InlineData(0xa2)]
    [InlineData(0xa5)]
    public void SnmpOtherPdusAreNotEnterpriseSet(int pdu)
        => Assert.False(SnmpEnterpriseSetInspector.TryInspect(Snmp((byte)pdu)));

    [Fact]
    public void BacnetBvlcRegistrationRequiresCompleteAttestedFrame()
    {
        byte[] wire={0x81,5,0,6,0,60};
        Assert.True(BacnetBvlcControlInspector.TryInspect(wire,true,out var result));
        Assert.Equal(BvlcControlFunction.RegisterForeignDevice,result.Function);
        Assert.Equal((ushort)60,result.RequestedTtlSeconds);
        Assert.False(BacnetBvlcControlInspector.TryInspect(wire,false,out _));
        Assert.False(BacnetBvlcControlInspector.TryInspect(wire[..^1],true,out _));
    }

    [Theory]
    [InlineData(1,true)]
    [InlineData(2,true)]
    [InlineData(0,false)]
    [InlineData(3,false)]
    public void BacnetCommunicationControlSeparatesEnableAndDisable(int state,bool expected)
    {
        byte[] wire={0x81,0x0a,0,12,1,4,0,5,7,17,0x19,(byte)state};
        Assert.Equal(expected,BacnetDeviceCommunicationControlInspector.TryInspect(wire,true,out var result));
        if(expected)Assert.Equal((byte)state,result.DisableState);
        Assert.False(BacnetDeviceCommunicationControlInspector.TryInspect(wire,false,out _));
    }

    [Fact]
    public void BacnetObjectListReadRequiresExactDeviceTarget()
    {
        byte[] wire={0x81,0x0a,0,17,1,4,0,5,7,12,0x0c,2,0,0,1,0x19,76};
        Assert.True(BacnetObjectListReadInspector.TryInspect(wire));
        for(int n=0;n<wire.Length;n++)Assert.False(BacnetObjectListReadInspector.TryInspect(wire.AsSpan(0,n)));
        wire[11]=0;
        Assert.False(BacnetObjectListReadInspector.TryInspect(wire));
    }

    [Theory]
    [InlineData(0,true)]
    [InlineData(1,true)]
    [InlineData(2,false)]
    public void BacnetRestartRequiresColdOrWarmStart(int state,bool expected)
    {
        byte[] wire={0x81,0x0a,0,12,1,4,0,5,7,20,9,(byte)state};
        Assert.Equal(expected,BacnetReinitializeDeviceInspector.TryInspect(wire));
        Assert.False(BacnetReinitializeDeviceInspector.TryInspect(wire[..^1]));
    }

    [Fact]
    public void BacnetScalarWriteRemainsDistinctFromEventDisable()
    {
        byte[] wire={0x81,0x0a,0,21,1,4,0,5,0x2a,15,0x0c,0,0x80,0,1,0x19,0x55,0x3e,0x21,1,0x3f};
        Assert.True(BacnetWritePropertyInspector.TryInspect(wire,true,out var result));
        Assert.True(result.HasObjectAndPropertyTarget);
        Assert.False(BacnetEventDisableInspector.TryInspect(wire));
        Assert.False(BacnetWritePropertyInspector.TryInspect(wire,false,out _));
        Assert.False(BacnetWritePropertyInspector.TryInspect(wire[..^1],true,out _));
    }

    // Independent bitwise CRC reference, not the production helper.
    private static ushort Crc(ReadOnlySpan<byte> bytes)
    {
        uint value=0;
        foreach(byte b in bytes)
        {
            value^=b;
            for(int bit=0;bit<8;bit++)value=(value>>1)^((value&1)!=0?0xa6bcu:0u);
        }
        return (ushort)~value;
    }
    private static byte[] Dnp(byte control,byte[] data)
    {
        var wire=new byte[10+data.Length+2*((data.Length+15)/16)];
        wire[0]=5;wire[1]=0x64;wire[2]=(byte)(5+data.Length);wire[3]=control;
        wire[4]=1;wire[6]=2;
        BinaryPrimitives.WriteUInt16LittleEndian(wire.AsSpan(8),Crc(wire.AsSpan(0,8)));
        int at=10;
        for(int i=0;i<data.Length;)
        {
            int n=Math.Min(16,data.Length-i);
            data.AsSpan(i,n).CopyTo(wire.AsSpan(at,n));
            BinaryPrimitives.WriteUInt16LittleEndian(wire.AsSpan(at+n),Crc(data.AsSpan(i,n)));
            i+=n;at+=n+2;
        }
        return wire;
    }

    [Fact]
    public void DnpRestartChecksBothCrcBlocks()
    {
        var wire=Dnp(0xc4,new byte[]{0xc0,0xc0,0x0d});
        Assert.True(Dnp3RestartRequestInspector.TryInspect(wire));
        wire[8]^=1;Assert.False(Dnp3RestartRequestInspector.TryInspect(wire));
        wire[8]^=1;wire[^1]^=1;Assert.False(Dnp3RestartRequestInspector.TryInspect(wire));
    }

    [Fact]
    public void DnpDisableRequiresAllThreeDistinctEventClasses()
    {
        byte[] data={0xc0,0xc0,0x15,60,2,6,60,3,6,60,4,6};
        var wire=Dnp(0xc4,data);
        Assert.True(Dnp3DisableUnsolicitedInspector.TryInspect(wire));
        Assert.False(Dnp3RestartRequestInspector.TryInspect(wire));
        data[10]=3;
        Assert.False(Dnp3DisableUnsolicitedInspector.TryInspect(Dnp(0xc4,data)));
        wire[^1]^=1;Assert.False(Dnp3DisableUnsolicitedInspector.TryInspect(wire));
    }

    [Fact]
    public void DnpUnsolicitedBinaryEventChecksShapeAndCrc()
    {
        var wire=Dnp(0x44,new byte[]{0xc0,0xf0,0x82,0,0,2,1,0x17,1,0,0x81});
        Assert.True(Dnp3UnsolicitedBinaryEventInspector.TryInspect(wire));
        Assert.False(Dnp3DisableUnsolicitedInspector.TryInspect(wire));
        wire[^1]^=1;Assert.False(Dnp3UnsolicitedBinaryEventInspector.TryInspect(wire));
    }

    [Fact]
    public void ModbusSingleRegisterRetainsOnlyPointAndRejectsOtherFunctions()
    {
        byte[] wire={0,1,0,0,0,6,1,6,0,42,0,99};
        Assert.True(ModbusSingleRegisterWriteInspector.TryInspect(wire,out uint point));
        Assert.Equal(0x1002au,point);
        wire[7]=3;Assert.False(ModbusSingleRegisterWriteInspector.TryInspect(wire,out _));
        Assert.False(ModbusSingleRegisterWriteInspector.TryInspect(wire[..^1],out _));
    }

    [Fact]
    public void ModbusClearMaskRequiresExactZeroMasks()
    {
        byte[] wire={0,1,0,0,0,8,1,0x16,0,42,0,0,0,0};
        Assert.True(ModbusClearMaskWriteInspector.TryInspect(wire));
        wire[13]=1;Assert.False(ModbusClearMaskWriteInspector.TryInspect(wire));
        wire[13]=0;wire[6]=0;Assert.False(ModbusClearMaskWriteInspector.TryInspect(wire));
    }
}
