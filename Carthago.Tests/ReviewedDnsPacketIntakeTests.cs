// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.IO;
using System.Threading.Tasks;
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
    [InlineData("record-truncated", false)]
    [InlineData("oversized-snap", false)]
    [InlineData("unsupported-link", false)]
    [InlineData("unsupported-magic", false)]
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
        if (change == "record-truncated") Write(36, (uint)frame.Length + 1);
        if (change == "oversized-snap") Write(16, 65536);
        if (change == "unsupported-link") Write(20, 101);
        if (change == "unsupported-magic") Write(0, 0xa1b23c4d);
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
        using var reviewer = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] key = reviewer.ExportSubjectPublicKeyInfo();
        var intake = new ReviewedDnsAuthenticatedIntake(key, scope);
        byte[] signature = reviewer.SignData(manifest, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        Assert.Equal(expected, intake.Matches(manifest, signature, capture,
            "192.0.2.1", "sensor", "interface", "network"));
        if (change == "valid")
        {
            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            byte[] wrong = other.SignData(manifest, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.False(intake.Matches(manifest, wrong, capture,
                "192.0.2.1", "sensor", "interface", "network"));
            Assert.False(intake.Matches(manifest, signature, capture,
                "192.0.2.1", "other", "interface", "network"));
            byte[] altered = (byte[])manifest.Clone();
            altered[0] ^= 1;
            Assert.False(intake.Matches(altered, signature, capture,
                "192.0.2.1", "sensor", "interface", "network"));
            byte[] changedCapture = (byte[])capture.Clone();
            changedCapture[^1] ^= 1;
            Assert.False(intake.Matches(manifest, signature, changedCapture,
                "192.0.2.1", "sensor", "interface", "network"));
            // Even a correctly signed manifest for another scope is not authorized.
            var otherScope = QualifiedDnsScope.Create("192.0.2.1", "other", "interface", "network");
            byte[] otherManifest = JsonSerializer.SerializeToUtf8Bytes(new {
                version = 1, scope = otherScope.Subject, captureSha256 = Hash(capture),
                startUtc = start.ToString("O"), endUtc = start.AddMinutes(1).ToString("O"),
                classification = "reviewed-benign", reviewId = "test-other"
            });
            byte[] otherSignature = reviewer.SignData(otherManifest, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.True(ReviewedDnsPacketIntake.Matches(otherManifest, Hash(otherManifest), capture,
                "192.0.2.1", "other", "interface", "network"));
            Assert.False(intake.Matches(otherManifest, otherSignature, capture,
                "192.0.2.1", "other", "interface", "network"));
            var otherIntake = new ReviewedDnsAuthenticatedIntake(key, otherScope);
            Assert.True(otherIntake.Matches(otherManifest, otherSignature, capture,
                "192.0.2.1", "other", "interface", "network"));
            Assert.False(intake.Matches(manifest, signature, capture,
                "192.0.2.1", "sensor", "interface", "other"));
            Assert.True(intake.TryValidate(manifest, signature, capture,
                "192.0.2.1", "sensor", "interface", "network", out var originalDigest, out var originalIds));
            Assert.Single(originalIds);
            Assert.True(intake.TryValidate(manifest, signature, capture,
                "192.0.2.1", "sensor", "interface", "network", out _, out var timedIds, out var ticks));
            Assert.Equal(originalIds, timedIds);
            Assert.Equal(new[] { start.UtcDateTime.Ticks }, ticks);
            Assert.False(intake.TryValidate(manifest, wrong, capture,
                "192.0.2.1", "sensor", "interface", "network", out _, out var rejectedIds, out var rejectedTicks));
            Assert.Empty(rejectedIds);
            Assert.Empty(rejectedTicks);
            byte[] repacked = (byte[])capture.Clone();
            repacked[16] = 0xfe; // different snaplen, same packet
            repacked[40] = 0x42; // different Ethernet address
            repacked[40 + 40] = 0x12; // UDP checksum
            byte[] RepackManifest(byte[] bytes) => JsonSerializer.SerializeToUtf8Bytes(new {
                version = 1, scope = scope.Subject, captureSha256 = Hash(bytes),
                startUtc = start.ToString("O"), endUtc = start.AddMinutes(1).ToString("O"),
                classification = "reviewed-benign", reviewId = "repacked"
            });
            byte[] repackedManifest = RepackManifest(repacked);
            byte[] repackedSignature = reviewer.SignData(repackedManifest, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.True(intake.TryValidate(repackedManifest, repackedSignature, repacked,
                "192.0.2.1", "sensor", "interface", "network", out var repackedDigest, out var repackedIds));
            Assert.NotEqual(originalDigest, repackedDigest);
            Assert.Equal(originalIds, repackedIds);
            // Duplicate records in one container yield one observation identity.
            byte[] repeated = new byte[capture.Length + capture.Length - 24];
            capture.CopyTo(repeated, 0);
            Array.Copy(capture, 24, repeated, capture.Length, capture.Length - 24);
            byte[] repeatedManifest = RepackManifest(repeated);
            byte[] repeatedSignature = reviewer.SignData(repeatedManifest, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.True(intake.TryValidate(repeatedManifest, repeatedSignature, repeated,
                "192.0.2.1", "sensor", "interface", "network", out _, out var repeatedIds));
            Assert.Equal(originalIds, repeatedIds);
            BinaryPrimitives.WriteUInt32LittleEndian(repeated.AsSpan(capture.Length + 4), 1);
            repeatedManifest = RepackManifest(repeated);
            repeatedSignature = reviewer.SignData(repeatedManifest, HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            Assert.True(intake.TryValidate(repeatedManifest, repeatedSignature, repeated,
                "192.0.2.1", "sensor", "interface", "network", out _, out var distinctIds));
            Assert.Equal(2, distinctIds.Length);
            Assert.Contains(originalIds[0], distinctIds);
            Assert.True(intake.TryValidate(repeatedManifest, repeatedSignature, repeated,
                "192.0.2.1", "sensor", "interface", "network", out _, out var orderedIds, out var orderedTicks));
            Assert.Equal(distinctIds, orderedIds);
            Assert.Equal(start.UtcDateTime.Ticks, orderedTicks[Array.IndexOf(orderedIds, originalIds[0])]);
            Assert.Contains(start.UtcDateTime.Ticks + 10, orderedTicks);
            string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);
            try
            {
                var admission = new ReviewedDnsCaptureAdmission(directory, intake);
                Assert.False(admission.TryReserve(manifest, wrong, capture,
                    "192.0.2.1", "sensor", "interface", "network"));
                Assert.Empty(Directory.GetFiles(directory));
                bool[] accepted = new bool[8];
                Parallel.For(0, accepted.Length, i => accepted[i] =
                    admission.TryReserve(manifest, signature, capture,
                        "192.0.2.1", "sensor", "interface", "network"));
                Assert.Single(Array.FindAll(accepted, value => value));
                var reopened = new ReviewedDnsCaptureAdmission(directory, intake);
                Assert.False(reopened.TryReserve(manifest, signature, capture,
                    "192.0.2.1", "sensor", "interface", "network"));
                var alternate = new ReviewedDnsCaptureAdmission(directory, otherIntake);
                Assert.False(alternate.TryReserve(otherManifest, otherSignature, capture,
                    "192.0.2.1", "other", "interface", "network"));
                Assert.False(reopened.TryReserve(repackedManifest, repackedSignature, repacked,
                    "192.0.2.1", "sensor", "interface", "network"));
                Assert.False(reopened.TryReserve(repeatedManifest, repeatedSignature, repeated,
                    "192.0.2.1", "sensor", "interface", "network"));
                // The new observation in the rejected mixed capture was not reserved.
                byte[] fresh = (byte[])capture.Clone();
                BinaryPrimitives.WriteUInt32LittleEndian(fresh.AsSpan(28), 1);
                byte[] freshManifest = RepackManifest(fresh);
                byte[] freshSignature = reviewer.SignData(freshManifest, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                Assert.True(reopened.TryReserve(freshManifest, freshSignature, fresh,
                    "192.0.2.1", "sensor", "interface", "network"));
                Assert.Single(Directory.GetFiles(directory));
                string journalPath = Path.Combine(directory, "admission.v2");
                byte[] goodJournal = File.ReadAllBytes(journalPath);
                string scopeDigest = Hash(System.Text.Encoding.UTF8.GetBytes(scope.Subject));
                string[] records = System.Text.Encoding.ASCII.GetString(goodJournal).Split('\n',
                    StringSplitOptions.RemoveEmptyEntries);
                Assert.Equal(2, records.Length);
                Assert.Equal(originalDigest + "," + scopeDigest + "," + originalIds[0] + ":" +
                    start.UtcDateTime.Ticks.ToString("X16"), records[0]);
                Assert.Contains(":" + (start.UtcDateTime.Ticks + 10).ToString("X16"), records[1]);
                string legacyPath = Path.Combine(directory, "admission.v1");
                File.WriteAllText(legacyPath, "legacy");
                Assert.False(reopened.TryReserve(manifest, signature, capture,
                    "192.0.2.1", "sensor", "interface", "network"));
                File.Delete(legacyPath);
                byte[] third = (byte[])capture.Clone();
                BinaryPrimitives.WriteUInt32LittleEndian(third.AsSpan(28), 2);
                byte[] thirdManifest = RepackManifest(third);
                byte[] thirdSignature = reviewer.SignData(thirdManifest, HashAlgorithmName.SHA256,
                    DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
                foreach (string corrupt in new[] { "torn", "\r\n", new string('A', 65) + "\n",
                    new string('A', 64) + ",," + new string('B', 64) + "\n",
                    new string('A', 64) + "," + new string('b', 64) + "\n",
                    new string('A', 64) + "," + new string('C', 64) + "," + new string('B', 64) + "\n",
                    new string('A', 64) + "," + new string('B', 64) + "," + new string('B', 64) + "\n",
                    new string('A', 64) + "," + scopeDigest + "," + new string('B', 64) + ":FFFFFFFFFFFFFFFF\n",
                    new string('A', 64) + "," + scopeDigest + "," + new string('B', 64) + ":0000000000000000\n",
                    System.Text.Encoding.ASCII.GetString(goodJournal) })
                {
                    File.WriteAllBytes(journalPath, goodJournal);
                    File.AppendAllText(journalPath, corrupt);
                    byte[] before = File.ReadAllBytes(journalPath);
                    Assert.False(reopened.TryReserve(thirdManifest, thirdSignature, third,
                        "192.0.2.1", "sensor", "interface", "network"));
                    Assert.Equal(before, File.ReadAllBytes(journalPath));
                }
                File.WriteAllBytes(journalPath, goodJournal);
                Assert.True(reopened.TryReserve(thirdManifest, thirdSignature, third,
                    "192.0.2.1", "sensor", "interface", "network"));
                var missing = new ReviewedDnsCaptureAdmission(Path.Combine(directory, "missing"), intake);
                Assert.False(missing.TryReserve(manifest, signature, capture,
                    "192.0.2.1", "sensor", "interface", "network"));
            }
            finally { Directory.Delete(directory, recursive: true); }
            Array.Clear(key, 0, key.Length);
            Assert.True(intake.Matches(manifest, signature, capture,
                "192.0.2.1", "sensor", "interface", "network"));
        }
        Assert.Equal(expected, ReviewedDnsPacketIntake.Matches(manifest, Hash(manifest), capture,
            "192.0.2.1", "sensor", "interface", "network"));
    }
}
