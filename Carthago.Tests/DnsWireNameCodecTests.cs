// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Contract tests for lossless DNS labels. These intentionally precede the
/// production codec: the first focused run must fail at the missing contract.
/// Raw label values here are synthetic and are not taken from the held-out PCAP.
/// </summary>
public sealed class DnsWireNameCodecTests
{
    [Fact]
    public void RoundTrips_Binary_Label_Byte_For_Byte()
    {
        byte[] binary = { 0x00, 0x2e, 0x5c, 0x7f, 0x80, 0xff };
        var encoded = Convert.ToBase64String(binary);

        Assert.True(DnsWireNameCodec.TryFromBase64Labels(
            new[] { encoded, "Y29t" }, out var name, out var error));
        Assert.Equal(DnsWireNameError.None, error);
        Assert.NotNull(name);
        Assert.Equal(2, name.LabelCount);
        Assert.Equal(binary, name.GetLabelBytes(0));
        Assert.Equal(new byte[] { (byte)'c', (byte)'o', (byte)'m' },
            name.GetLabelBytes(1));
        Assert.Equal(new[] { encoded, "Y29t" },
            DnsWireNameCodec.ToBase64Labels(name));
        Assert.False(DnsWireNameCodec.TryGetSafeAsciiQName(name, out var display));
        Assert.Null(display);

        // Caller mutations must never affect identity or exported evidence.
        var copy = name.GetLabelBytes(0);
        copy[0] = 0x41;
        Assert.Equal(binary, name.GetLabelBytes(0));
    }

    [Fact]
    public void Literal_Dot_Octet_Does_Not_Become_A_Label_Separator()
    {
        var original = new byte[] { (byte)'a', (byte)'.', (byte)'b' };
        Assert.True(DnsWireNameCodec.TryFromBase64Labels(
            new[] { Convert.ToBase64String(original), "Y29t" },
            out var name, out _));

        Assert.NotNull(name);
        Assert.Equal(2, name.LabelCount);
        Assert.Equal(original, name.GetLabelBytes(0));
        Assert.False(DnsWireNameCodec.TryGetSafeAsciiQName(name, out _));
    }

    [Fact]
    public void Preserves_Legacy_Safe_Printable_Name()
    {
        Assert.True(DnsWireNameCodec.TryFromBase64Labels(
            Encode("www", "Example", "COM"), out var name, out _));

        Assert.NotNull(name);
        Assert.True(DnsWireNameCodec.TryGetSafeAsciiQName(name, out var display));
        Assert.Equal("www.Example.COM", display);
    }

    [Fact]
    public void Accepts_63_Octet_Label_And_Rejects_64_Octet_Label()
    {
        Assert.True(DnsWireNameCodec.TryFromBase64Labels(
            Encode(new string('a', 63)), out var valid, out var validError));
        Assert.NotNull(valid);
        Assert.Equal(DnsWireNameError.None, validError);

        Assert.False(DnsWireNameCodec.TryFromBase64Labels(
            Encode(new string('a', 64)), out var invalid, out var error));
        Assert.Null(invalid);
        Assert.NotEqual(DnsWireNameError.None, error);
    }

    [Fact]
    public void Rejects_Overlong_Decompressed_Name()
    {
        // 63+63+63+61 label octets + four length octets + root = 255.
        Assert.True(DnsWireNameCodec.TryFromBase64Labels(
            Encode(new string('a', 63), new string('b', 63),
                new string('c', 63), new string('d', 61)),
            out var max, out var validError));
        Assert.NotNull(max);
        Assert.Equal(255, max.DecompressedLength);
        Assert.Equal(DnsWireNameError.None, validError);

        Assert.False(DnsWireNameCodec.TryFromBase64Labels(
            Encode(new string('a', 63), new string('b', 63),
                new string('c', 63), new string('d', 62)),
            out var tooLong, out var error));
        Assert.Null(tooLong);
        Assert.NotEqual(DnsWireNameError.None, error);
    }

    [Fact]
    public void Identity_Folds_Only_ASCII_Case()
    {
        var upper = Decode(new byte[] { (byte)'A', (byte)'Z', 0x80, 0xff });
        var lower = Decode(new byte[] { (byte)'a', (byte)'z', 0x80, 0xff });
        var differentHighOctet = Decode(new byte[] { (byte)'a', (byte)'z', 0xa0, 0xff });

        Assert.Equal(DnsWireNameCodec.CanonicalIdentityKey(upper),
            DnsWireNameCodec.CanonicalIdentityKey(lower));
        Assert.NotEqual(DnsWireNameCodec.CanonicalIdentityKey(upper),
            DnsWireNameCodec.CanonicalIdentityKey(differentHighOctet));
        Assert.NotEqual(DnsWireNameCodec.ToBase64Labels(upper)[0],
            DnsWireNameCodec.ToBase64Labels(lower)[0]);
    }

    [Fact]
    public void Identity_Respects_Original_Label_Boundaries()
    {
        var split = Decode(new byte[] { (byte)'a' }, new byte[] { (byte)'b' });
        var joined = Decode(new byte[] { (byte)'a', (byte)'b' });
        Assert.NotEqual(DnsWireNameCodec.CanonicalIdentityKey(split),
            DnsWireNameCodec.CanonicalIdentityKey(joined));
    }

    [Theory]
    [InlineData("AR==")] // Non-zero unused padding bits (would decode to 0x01).
    [InlineData("AQ=")]
    [InlineData("AQ")]
    [InlineData("AQ==\n")]
    [InlineData("_w==")]
    [InlineData("")]
    public void Rejects_Noncanonical_Base64(string invalid)
    {
        Assert.False(DnsWireNameCodec.TryFromBase64Labels(
            new[] { invalid }, out var name, out var error));
        Assert.Null(name);
        Assert.NotEqual(DnsWireNameError.None, error);
    }

    [Fact]
    public void Rejects_Null_Labels_Without_Partial_Result()
    {
        Assert.False(DnsWireNameCodec.TryFromBase64Labels(
            new string[] { "YQ==", null! }, out var name, out var error));
        Assert.Null(name);
        Assert.NotEqual(DnsWireNameError.None, error);
    }

    [Fact]
    public void Reads_Uncompressed_Wire_Name_Without_Byte_Replacement()
    {
        byte[] wire = { 3, 0x2e, 0x80, 0xff, 3, (byte)'C', (byte)'O', (byte)'M', 0,
            0, 16, 0, 1 }; // QTYPE TXT and QCLASS IN follow the QNAME.

        Assert.True(DnsWireNameCodec.TryReadQuestion(wire, 0,
            out var name, out var nextOffset, out var error));
        Assert.NotNull(name);
        Assert.Equal(9, nextOffset);
        Assert.Equal(DnsWireNameError.None, error);
        Assert.Equal(new byte[] { 0x2e, 0x80, 0xff }, name.GetLabelBytes(0));
        Assert.Equal(new byte[] { (byte)'C', (byte)'O', (byte)'M' },
            name.GetLabelBytes(1));
    }

    [Fact]
    public void Reads_Backward_Compressed_Pointer_And_Preserves_Question_Offset()
    {
        byte[] wire = { 3, (byte)'c', (byte)'o', (byte)'m', 0,
            3, (byte)'W', (byte)'w', (byte)'w', 0xc0, 0x00, 0, 16, 0, 1 };

        Assert.True(DnsWireNameCodec.TryReadQuestion(wire, 5,
            out var name, out var nextOffset, out var error));
        Assert.NotNull(name);
        Assert.Equal(11, nextOffset);
        Assert.Equal(new[] { "V3d3", "Y29t" },
            DnsWireNameCodec.ToBase64Labels(name));
        Assert.Equal(DnsWireNameError.None, error);
    }

    [Theory]
    [InlineData(new byte[] { 0xc0, 0x00 }, 0)] // Self-referential pointer.
    [InlineData(new byte[] { 0xc0, 0x02, 0 }, 0)] // Forward pointer.
    [InlineData(new byte[] { 0xc0 }, 0)] // Missing second pointer octet.
    [InlineData(new byte[] { 3, (byte)'a' }, 0)] // Truncated label.
    [InlineData(new byte[] { 0x40, 0 }, 0)] // Unsupported extended-label type.
    [InlineData(new byte[] { 0xc0, 0xff }, 0)] // Pointer outside message.
    public void Rejects_Compression_Cycle_And_Forward_Pointer(byte[] wire, int offset)
    {
        Assert.False(DnsWireNameCodec.TryReadQuestion(wire, offset,
            out var name, out _, out var error));
        Assert.Null(name);
        Assert.NotEqual(DnsWireNameError.None, error);
    }

    private static DnsWireName Decode(params byte[][] labels)
    {
        Assert.True(DnsWireNameCodec.TryFromBase64Labels(
            labels.Select(Convert.ToBase64String).ToArray(), out var name, out _));
        return Assert.IsType<DnsWireName>(name);
    }

    private static string[] Encode(params string[] labels) => labels
        .Select(label => Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes(label)))
        .ToArray();
}
