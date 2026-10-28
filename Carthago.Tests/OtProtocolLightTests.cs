// SPDX-License-Identifier: MIT
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;
public sealed class OtProtocolLightTests
{
    private static readonly byte[] ModbusReadHolding =
        { 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x01 };
    private static readonly byte[] S7Setup =
        { 0x03, 0x00, 0x00, 0x11, 0x02, 0xf0, 0x80, 0x32, 0x01,
          0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00 };
    // DNP3 link header 05 64 05 C0 01 00 02 00 with CRC-16/DNP 0xE374.
    private static readonly byte[] Dnp3Header =
        { 0x05, 0x64, 0x05, 0xc0, 0x01, 0x00, 0x02, 0x00, 0x74, 0xe3 };
    private static readonly byte[] BacnetBvlc =
        { 0x81, 0x0a, 0x00, 0x06, 0x01, 0x20 };

    [Fact] public void Modbus_Write_Single_Register_Request_Is_Typed_Write()
    {
        var bytes = (byte[])ModbusReadHolding.Clone(); bytes[7] = 6;
        Assert.True(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 502, out var protocol));
        Assert.Equal("modbus.write", protocol);
    }
    [Fact] public void Modbus_Write_Response_Is_Not_New_Write_Request()
    {
        var bytes = (byte[])ModbusReadHolding.Clone(); bytes[7] = 6;
        Assert.True(OtProtocolLight.TryIdentifyTcp(bytes, 502, 51000, out var protocol));
        Assert.Equal("modbus", protocol);
    }
    [Fact] public void Modbus_Read_Holding_Register_Remains_Read()
    {
        Assert.True(OtProtocolLight.TryIdentifyTcp(ModbusReadHolding, 51000, 502, out var protocol));
        Assert.Equal("modbus", protocol);
    }
    [Fact] public void Modbus_Unknown_Function_Remains_Generic()
    {
        var bytes = (byte[])ModbusReadHolding.Clone(); bytes[7] = 4;
        Assert.True(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 502, out var protocol));
        Assert.Equal("modbus", protocol);
    }
    [Fact] public void Modbus_Mbap_And_Function_Code_Identify_Tcp_502()
    {
        Assert.True(OtProtocolLight.TryIdentifyTcp(ModbusReadHolding, 51000, 502, out var protocol));
        Assert.Equal("modbus", protocol);
    }
    [Fact] public void Modbus_Nonzero_Mbap_Protocol_Id_Is_Not_Modbus()
    {
        var bytes = (byte[])ModbusReadHolding.Clone(); bytes[3] = 1;
        Assert.False(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 502, out _));
    }
    [Fact] public void Modbus_Truncated_Length_Is_Not_Parsed()
    {
        var bytes = (byte[])ModbusReadHolding.Clone(); bytes[5] = 40;
        Assert.False(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 502, out _));
    }
    [Fact] public void S7_Tpkt_Cotp_And_S7_Header_Identify_Tcp_102()
    {
        Assert.True(OtProtocolLight.TryIdentifyTcp(S7Setup, 51000, 102, out var protocol));
        Assert.Equal("s7comm", protocol);
    }
    [Fact] public void S7_Broken_Cotp_Does_Not_Identify_Plc_Traffic()
    {
        var bytes = (byte[])S7Setup.Clone(); bytes[5] = 0xff;
        Assert.False(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 102, out _));
    }
    [Fact] public void S7_Tpkt_Length_Beyond_Capture_Is_Rejected()
    {
        var bytes = (byte[])S7Setup.Clone(); bytes[3] = 0x20;
        Assert.False(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 102, out _));
    }
    [Fact] public void Dnp3_Link_Header_With_Correct_Crc_Identifies_Tcp_20000()
    {
        Assert.True(OtProtocolLight.TryIdentifyTcp(Dnp3Header, 51000, 20000, out var protocol));
        Assert.Equal("dnp3", protocol);
    }
    [Fact] public void Dnp3_Header_Crc_Mismatch_Is_Rejected()
    {
        var bytes = (byte[])Dnp3Header.Clone(); bytes[9] ^= 0x01;
        Assert.False(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 20000, out _));
    }
    [Fact] public void Bacnet_Bvlc_Length_And_Npdu_Identify_Udp_47808()
    {
        Assert.True(OtProtocolLight.TryIdentifyUdp(BacnetBvlc, 51000, 47808, out var protocol));
        Assert.Equal("bacnet", protocol);
    }
    [Fact] public void Bacnet_Mismatched_Bvlc_Length_Is_Rejected()
    {
        var bytes = (byte[])BacnetBvlc.Clone(); bytes[3] = 0x20;
        Assert.False(OtProtocolLight.TryIdentifyUdp(bytes, 51000, 47808, out _));
    }
    [Fact] public void Port_Only_Random_Payload_Does_Not_Establish_Protocol()
    {
        var bytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };
        Assert.False(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 20000, out _));
        Assert.False(OtProtocolLight.TryIdentifyTcp(bytes, 51000, 102, out _));
        Assert.False(OtProtocolLight.TryIdentifyUdp(bytes, 51000, 47808, out _));
    }

    [Fact] public void Bacnet_WhoIs_Bvlc_Npdu_Apdu_Is_Parsed()
    {
        byte[] p = { 0x81, 0x0b, 0x00, 0x08, 0x01, 0x00, 0x10, 0x08 };
        Assert.True(OtProtocolLight.TryIdentifyUdp(p, 51000, 47808, out var kind));
        Assert.Equal("bacnet.whois", kind);
    }
    [Fact] public void Bacnet_IAm_Bvlc_Npdu_Apdu_Is_Parsed()
    {
        byte[] p = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x00 };
        Assert.True(OtProtocolLight.TryIdentifyUdp(p, 47808, 51000, out var kind));
        Assert.Equal("bacnet.iam", kind);
    }
    [Fact] public void Bacnet_Without_Discovery_Apdu_Remains_Generic()
    {
        byte[] p = { 0x81, 0x0a, 0x00, 0x08, 0x01, 0x00, 0x10, 0x0f };
        Assert.True(OtProtocolLight.TryIdentifyUdp(p, 51000, 47808, out var kind));
        Assert.Equal("bacnet", kind);
    }
    [Fact] public void Ntp_Mode7_Monlist_Request_Is_Parsed()
    {
        byte[] p = { 0x27, 0x00, 0x03, 0x2a, 0, 0, 0, 0 };
        Assert.True(OtProtocolLight.TryIdentifyUdp(p, 51000, 123, out var kind));
        Assert.Equal("ntp.mode7.monlist", kind);
    }
    [Fact] public void Ntp_Normal_Client_Sync_Is_Not_Monlist()
    {
        byte[] p = { 0x23, 0x00, 0x03, 0x2a, 0, 0, 0, 0 };
        Assert.False(OtProtocolLight.TryIdentifyUdp(p, 51000, 123, out _));
    }
    [Fact] public void Ntp_Mode7_Response_Is_Not_Request()
    {
        byte[] p = { 0x27, 0x80, 0x03, 0x2a, 0, 0, 0, 0 };
        Assert.False(OtProtocolLight.TryIdentifyUdp(p, 123, 51000, out _));
    }
}
