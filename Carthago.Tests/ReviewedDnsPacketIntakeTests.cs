// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using Carthago.Services.Baseline;
using Xunit;

namespace Carthago.Tests;

public sealed class ReviewedDnsPacketIntakeTests
{
    private static string Hash(byte[] b) => Convert.ToHexString(SHA256.HashData(b));

    [Theory]
    [InlineData("valid", true)]
    [InlineData("source", false)]
    [InlineData("interval", false)]
    [InlineData("truncated", false)]
    [InlineData("response", false)]
    [InlineData("fragment", false)]
    [InlineData("empty", false)]
    [InlineData("bad-micros", false)]
    [InlineData("trailing-frame", false)]
    [InlineData("two-valid", true)]
    [InlineData("second-source", false)]
    [InlineData("reverse-time", false)]
    [InlineData("second-outside", false)]
    public void Packet_Bytes_Determine_Source_And_Time(string change, bool expected)
    {
        var start = new DateTimeOffset(2026, 11, 13, 10, 0, 0, TimeSpan.Zero);
        byte[] frame = new byte[14 + 20 + 8 + 19];
        frame[12] = 8; frame[14] = 0x45; frame[17] = 47; frame[23] = 17;
        frame[26] = 192; frame[28] = 2; frame[29] = 1;
        frame[34] = 0x12; frame[35] = 0x34; frame[37] = 53; frame[39] = 27;
        frame[47] = 1; frame[54] = 1; frame[55] = (byte)'a'; frame[56] = 0;
        frame[58] = 1; frame[60] = 1;
        if (change == "source") frame[29] = 2;
        if (change == "response") frame[44] = 0x80;
        if (change == "fragment") frame[20] = 0x20;
        if (change == "trailing-frame") Array.Resize(ref frame, frame.Length + 1);
        byte[] capture = new byte[40 + frame.Length];
        void Write(int p, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(capture.AsSpan(p), v);
        Write(0, 0xa1b2c3d4); capture[4] = 2; capture[6] = 4;
        Write(16, 65535); Write(20, 1);
        Write(24, (uint)start.ToUnixTimeSeconds());
        Write(28, change == "bad-micros" ? 1000000u : 0u);
        Write(32, (uint)frame.Length); Write(36, (uint)frame.Length);
        frame.CopyTo(capture, 40);
        if (change == "truncated") Array.Resize(ref capture, capture.Length - 1);
        if (change == "empty") Array.Resize(ref capture, 24);
        if (change is "two-valid" or "second-source" or "reverse-time" or "second-outside")
        {
            int second = capture.Length;
            Array.Resize(ref capture, second + 16 + frame.Length);
            Array.Copy(capture, 24, capture, second, 16 + frame.Length);
            Write(second, (uint)start.AddSeconds(change == "reverse-time" ? -1 :
                change == "second-outside" ? 61 : 1).ToUnixTimeSeconds());
            if (change == "second-source") capture[second + 16 + 29] = 2;
        }
        var scope = QualifiedDnsScope.Create("192.0.2.1", "sensor", "interface", "network");
        byte[] manifest = JsonSerializer.SerializeToUtf8Bytes(new {
            version = 1, scope = scope.Subject, captureSha256 = Hash(capture),
            startUtc = (change == "interval" ? start.AddSeconds(1) : start).ToString("O"),
            endUtc = start.AddMinutes(1).ToString("O"), classification = "reviewed-benign", reviewId = "test"
        });
        Assert.Equal(expected, ReviewedDnsPacketIntake.Matches(manifest, Hash(manifest), capture,
            "192.0.2.1", "sensor", "interface", "network"));
    }
}
