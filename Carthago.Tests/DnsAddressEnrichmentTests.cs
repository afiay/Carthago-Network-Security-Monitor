using System;
using System.Collections.Generic;
using System.Buffers.Binary;
using PacketDotNet;
using System.Net;
using System.Text;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.ProtocolIntelligence;

namespace Carthago.Tests;

public sealed class DnsAddressEnrichmentTests
{
    private static byte[] Name(string name)
    {
        var bytes = new List<byte>();
        foreach (var label in name.Split('.'))
        {
            bytes.Add((byte)label.Length);
            bytes.AddRange(Encoding.ASCII.GetBytes(label));
        }
        bytes.Add(0);
        return bytes.ToArray();
    }

    private static void U16(List<byte> b, int v) { b.Add((byte)(v >> 8)); b.Add((byte)v); }
    private static void U32(List<byte> b, uint v) { b.Add((byte)(v >> 24)); b.Add((byte)(v >> 16)); b.Add((byte)(v >> 8)); b.Add((byte)v); }
    private static byte[] Rr(string owner, int type, uint ttl, byte[] data)
    {
        var b = new List<byte>(Name(owner));
        U16(b, type); U16(b, 1); U32(b, ttl); U16(b, data.Length); b.AddRange(data);
        return b.ToArray();
    }
    private static byte[] Ip(string ip) => IPAddress.Parse(ip).GetAddressBytes();
    private static byte[] Wire(int type, bool response, params byte[][] records)
    {
        var b = new List<byte>();
        U16(b, 7); U16(b, response ? 0x8180 : 0x0100);
        U16(b, 1); U16(b, records.Length); U16(b, 0); U16(b, 0);
        b.AddRange(Name("example.com")); U16(b, type); U16(b, 1);
        foreach (var record in records) b.AddRange(record);
        return b.ToArray();
    }

    [Fact]
    public void Multi_A_Answers_And_Unrelated_Owner()
    {
        Assert.True(DnsAddressObservationInspector.TryInspect(Wire(1, true,
            Rr("example.com", 1, 60, Ip("8.8.8.8")),
            Rr("example.com", 1, 30, Ip("1.1.1.1")),
            Rr("unrelated.example", 1, 99, Ip("9.9.9.9"))), out var result));
        Assert.Equal(2, result!.Answers.Count);
        Assert.Contains(result.Answers, a => a.Address == "8.8.8.8" && a.Ttl == 60);
        Assert.DoesNotContain(result.Answers, a => a.Address == "9.9.9.9");
    }

    [Fact]
    public void Aaaa_And_Cname_Chain_Use_Minimum_Ttl()
    {
        Assert.True(DnsAddressObservationInspector.TryInspect(Wire(28, true,
            Rr("example.com", 5, 15, Name("alias.example")),
            Rr("alias.example", 5, 20, Name("end.example")),
            Rr("end.example", 28, 90, Ip("2001:4860::1"))), out var result));
        var answer = Assert.Single(result!.Answers);
        Assert.Equal("2001:4860::1", answer.Address);
        Assert.Equal(15u, answer.Ttl);
    }

    [Fact]
    public void Cyclic_And_Conflicting_Aliases_Are_Rejected()
    {
        Assert.False(DnsAddressObservationInspector.TryInspect(Wire(1, true,
            Rr("example.com", 5, 10, Name("alias.example")),
            Rr("alias.example", 5, 10, Name("example.com"))), out _));
        Assert.False(DnsAddressObservationInspector.TryInspect(Wire(1, true,
            Rr("example.com", 5, 10, Name("a.example")),
            Rr("example.com", 5, 10, Name("b.example"))), out _));
    }

    [Fact]
    public void Truncated_Message_And_Invalid_Rdata_Are_Rejected()
    {
        var wire = Wire(28, true, Rr("example.com", 28, 60, Ip("2001:4860::1")));
        Assert.False(DnsAddressObservationInspector.TryInspect(wire.AsSpan(0, wire.Length - 1), out _));
        wire[2] |= 2; // TC
        Assert.False(DnsAddressObservationInspector.TryInspect(wire, out _));
        Assert.False(DnsAddressObservationInspector.TryInspect(Wire(28, true,
            Rr("example.com", 28, 60, Ip("8.8.8.8"))), out _));
    }

    [Fact]
    public void Question_Type_Must_Match_And_Ipv6_Correlates()
    {
        var cache = new DnsConnectionEnrichment();
        TrafficRecord Dns(byte[] wire, bool reply)
        {
            Assert.True(DnsAddressObservationInspector.TryInspect(wire, out var obs));
            return new TrafficRecord
            {
                Source = reply ? "2001:db8::53" : "2001:db8::10",
                Destination = reply ? "2001:db8::10" : "2001:db8::53",
                SourcePort = reply ? 53 : 50000, DestinationPort = reply ? 50000 : 53,
                IsUdp = true, SrcIsLocalHost = !reply, DstIsLocalHost = reply, DnsAddressObservation = obs
            };
        }
        TrafficRecord Flow() => new() { Source = "2001:db8::10", Destination = "2001:4860::1",
            SourcePort = 50001, DestinationPort = 443, IsTcp = true, SrcIsLocalHost = true };
        var answer = Wire(28, true, Rr("example.com", 28, 2, Ip("2001:4860::1")));
        cache.Observe(Dns(Wire(1, false), false), 100);
        cache.Observe(Dns(answer, true), 200);
        var wrong = Flow(); cache.Observe(wrong, 300);
        Assert.Null(wrong.DnsCorrelatedNames);
        cache.Observe(Dns(Wire(28, false), false), 400);
        cache.Observe(Dns(answer, true), 500);
        var ok = Flow(); cache.Observe(ok, 600);
        Assert.Equal("example.com", ok.DnsCorrelatedNames);
        var expired = Flow(); cache.Observe(expired, 2500);
        Assert.Null(expired.DnsCorrelatedNames);
    }

    [Fact]
    public void Packet_Producer_Multi_A_Does_Not_Qualify_Strict_Single_A()
    {
        var wire = Wire(1, true, Rr("example.com", 1, 60, Ip("8.8.8.8")),
            Rr("example.com", 1, 60, Ip("1.1.1.1")));
        var record = DnsCaptureQualificationTests.Parse(new PacketHandler(), wire, true);
        Assert.NotNull(record.DnsAddressObservation);
        Assert.Equal(2, record.DnsAddressObservation!.Answers.Count);
        Assert.False(record.DnsValidatedSingleAAnswer);
        var incomplete = DnsCaptureQualificationTests.Parse(new PacketHandler(), wire, true, inconsistentLength: true);
        Assert.Null(incomplete.DnsAddressObservation);
    }

    [Fact]
    public void Packet_Producer_Complete_Ipv6_Udp_Aaaa()
    {
        var wire = Wire(28, true, Rr("example.com", 28, 60, Ip("2001:4860::1")));
        var raw = new byte[48 + wire.Length];
        raw[0] = 0x60; raw[6] = 17; raw[7] = 64;
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(4, 2), (ushort)(8 + wire.Length));
        Ip("2001:db8::53").CopyTo(raw, 8);
        Ip("2001:db8::10").CopyTo(raw, 24);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(40, 2), 53);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(42, 2), 51000);
        BinaryPrimitives.WriteUInt16BigEndian(raw.AsSpan(44, 2), (ushort)(8 + wire.Length));
        wire.CopyTo(raw, 48);
        var record = Assert.IsType<TrafficRecord>(new PacketHandler().ParseFrame(raw, (LinkLayers)12));
        Assert.NotNull(record.DnsAddressObservation);
        Assert.Equal("2001:4860::1", Assert.Single(record.DnsAddressObservation!.Answers).Address);
        Assert.False(record.DnsValidatedAQuestion);
    }

    [Fact]
    public void Compressed_Answer_Owner_Is_Supported()
    {
        var rr = new List<byte> { 0xc0, 0x0c };
        U16(rr, 1); U16(rr, 1); U32(rr, 10); U16(rr, 4); rr.AddRange(Ip("8.8.8.8"));
        Assert.True(DnsAddressObservationInspector.TryInspect(Wire(1, true, rr.ToArray()), out var result));
        Assert.Equal("8.8.8.8", Assert.Single(result!.Answers).Address);
    }
}
