// SPDX-License-Identifier: MIT
#if CARTHAGO_DNS_WIRE_STAGE2
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Carthago.Models;
using Carthago.Services;
using PacketDotNet;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Authored-first binary DNS integration contracts. Pending RED/GREEN execution
/// on CARTHAGE at the owner's chosen test time; no source PCAP is embedded.
/// </summary>
public sealed class DnsWirePacketTests
{
    [Fact]
    public void PacketHandler_Preserves_Binary_Label_Without_Question_Marks()
    {
        byte[] firstLabel = { (byte)'x', 0x00, 0x80, 0xff };
        var packet = MakeUdpIpv4(DnsQuestion(firstLabel, Bytes("example"), Bytes("net")));

        var result = new PacketHandler().ParseFrame(packet, (LinkLayers)12);

        Assert.NotNull(result);
        Assert.Equal("DNS", result.ApplicationProtocol);
        Assert.Equal("TXT", result.DnsQtype);
        Assert.Null(result.DnsQname);
        Assert.Equal(new[] {
            Convert.ToBase64String(firstLabel), "ZXhhbXBsZQ==", "bmV0"
        }, result.DnsWireLabelsBase64);
        Assert.DoesNotContain("?", result.Info ?? string.Empty);
        Assert.DoesNotContain(Convert.ToBase64String(firstLabel), result.Info ?? string.Empty);
    }

    [Fact]
    public void PacketHandler_Preserves_Legacy_Ascii_DnsQname()
    {
        var packet = MakeUdpIpv4(DnsQuestion(Bytes("www"), Bytes("Example"), Bytes("net")));

        var result = new PacketHandler().ParseFrame(packet, (LinkLayers)12);

        Assert.NotNull(result);
        Assert.Equal("www.Example.net", result.DnsQname);
        Assert.Equal("TXT", result.DnsQtype);
        Assert.Equal(new[] { "d3d3", "RXhhbXBsZQ==", "bmV0" },
            result.DnsWireLabelsBase64);
    }

    [Fact]
    public void Does_Not_Split_Embedded_Dot_Octet()
    {
        byte[] label = Bytes("a.b");
        var packet = MakeUdpIpv4(DnsQuestion(label, Bytes("example")));

        var result = new PacketHandler().ParseFrame(packet, (LinkLayers)12);

        Assert.NotNull(result);
        Assert.Null(result.DnsQname);
        Assert.Equal(2, result.DnsWireLabelsBase64?.Count);
        Assert.Equal(Convert.ToBase64String(label), result.DnsWireLabelsBase64![0]);
    }

    [Fact]
    public void Default_Serialization_Omits_Wire_Labels()
    {
        byte[] binary = { 0x00, 0x2e, 0x80, 0xff };
        var encoded = Convert.ToBase64String(binary);
        var record = new TrafficRecord
        {
            DnsQname = null,
            DnsQtype = "TXT",
            DnsWireLabelsBase64 = new[] { encoded, "Y29t" }
        };

        var json = JsonSerializer.Serialize(record);

        Assert.DoesNotContain("DnsWireLabelsBase64", json, StringComparison.Ordinal);
        Assert.DoesNotContain("dnsWireLabelsBase64", json, StringComparison.Ordinal);
        Assert.DoesNotContain(encoded, json, StringComparison.Ordinal);
    }

    [Fact]
    public void DnsLight_Tcp_Uses_Two_Byte_Frame_Length()
    {
        byte[] dns = DnsQuestion(Bytes("www"), Bytes("example"), Bytes("org"));
        var framed = new byte[dns.Length + 2];
        framed[0] = (byte)(dns.Length >> 8);
        framed[1] = (byte)dns.Length;
        dns.CopyTo(framed, 2);

        Assert.True(PacketHandler.DnsLight.TryParse(framed, isTcp: true, out var parsed));
        Assert.Equal("www.example.org", parsed.QName);
        Assert.Equal("TXT", parsed.QType);
        Assert.Equal(new[] { "d3d3", "ZXhhbXBsZQ==", "b3Jn" },
            parsed.WireLabelsBase64);
    }

    [Theory]
    [InlineData(new byte[] { 0, 2, 1 }, true)] // TCP frame shorter than DNS header.
    [InlineData(new byte[] { 0, 100, 1, 2 }, true)] // TCP length beyond captured data.
    [InlineData(new byte[] { 0, 1, 2 }, false)] // UDP DNS header truncated.
    public void Rejects_Truncated_Dns_And_Tcp_Frames(byte[] payload, bool tcp)
    {
        Assert.False(PacketHandler.DnsLight.TryParse(payload, tcp, out var ignored));
        Assert.Null(ignored.QName);
    }

    private static byte[] Bytes(string text) => Encoding.ASCII.GetBytes(text);

    private static byte[] DnsQuestion(params byte[][] labels)
    {
        var bytes = new List<byte> {
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Standard query
            0x00, 0x01, // One question
            0, 0, 0, 0, 0, 0
        };
        foreach (var label in labels)
        {
            Assert.InRange(label.Length, 1, 63);
            bytes.Add((byte)label.Length);
            bytes.AddRange(label);
        }
        bytes.Add(0); // Terminal DNS root label
        bytes.AddRange(new byte[] { 0, 16, 0, 1 }); // TXT / IN
        return bytes.ToArray();
    }

    private static byte[] MakeUdpIpv4(byte[] dns)
    {
        var packet = new byte[20 + 8 + dns.Length];
        var totalLength = packet.Length;
        packet[0] = 0x45; // IPv4, five 32-bit header words
        packet[2] = (byte)(totalLength >> 8);
        packet[3] = (byte)totalLength;
        packet[8] = 64;
        packet[9] = 17; // UDP
        packet[12] = 10;
        packet[15] = 1;
        packet[16] = 10;
        packet[19] = 2;
        packet[20] = 0xcf; // Ephemeral source port 53000
        packet[21] = 0x08;
        packet[22] = 0;
        packet[23] = 53;
        int udpLength = 8 + dns.Length;
        packet[24] = (byte)(udpLength >> 8);
        packet[25] = (byte)udpLength;
        dns.CopyTo(packet, 28);
        return packet;
    }
}
#endif // CARTHAGO_DNS_WIRE_STAGE2
