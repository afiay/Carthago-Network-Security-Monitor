// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Carthago.Services.Baseline;
using Xunit;

namespace Carthago.Tests;

public sealed class ReviewedDnsJournalCheckpointTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("old", false)]
    [InlineData("future", false)]
    [InlineData("deployment", false)]
    [InlineData("domain", false)]
    [InlineData("wrong-key", false)]
    [InlineData("tampered", false)]
    [InlineData("trailing", false)]
    public void Signed_Checkpoint_Requires_Exact_Independent_Revision(string change, bool expected)
    {
        using var authority = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] deployment = SHA256.HashData(new byte[] { 1 });
        byte[] digest = SHA256.HashData(new byte[] { 2 });
        byte[] domain = Encoding.ASCII.GetBytes("CARTHAGO-DNS-JOURNAL-V2\0");
        byte[] checkpoint = new byte[domain.Length + 72];
        domain.CopyTo(checkpoint, 0);
        deployment.CopyTo(checkpoint, domain.Length);
        BinaryPrimitives.WriteUInt64BigEndian(checkpoint.AsSpan(domain.Length + 32),
            change == "old" ? 6UL : change == "future" ? 8UL : 7UL);
        digest.CopyTo(checkpoint, domain.Length + 40);
        if (change == "deployment") checkpoint[domain.Length] ^= 1;
        if (change == "domain") checkpoint[0] ^= 1;
        if (change == "trailing") Array.Resize(ref checkpoint, checkpoint.Length + 1);
        byte[] signature = (change == "wrong-key" ? other : authority).SignData(
            checkpoint, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        if (change == "tampered") checkpoint[^1] ^= 1;
        byte[] key = authority.ExportSubjectPublicKeyInfo();
        var verifier = new ReviewedDnsJournalCheckpoint(key, deployment, 7);
        Array.Clear(key, 0, key.Length);
        Array.Clear(deployment, 0, deployment.Length);
        Assert.Equal(expected, verifier.TryVerify(checkpoint, signature, out var actual));
        if (expected) Assert.Equal(digest, actual);
        else Assert.Empty(actual);
    }
}
