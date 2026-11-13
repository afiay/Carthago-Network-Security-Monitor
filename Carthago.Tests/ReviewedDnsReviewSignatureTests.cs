// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;
using Carthago.Services.Baseline;
using Xunit;

namespace Carthago.Tests;

public sealed class ReviewedDnsReviewSignatureTests
{
    [Theory]
    [InlineData("valid", true)]
    [InlineData("modified", false)]
    [InlineData("wrong-key", false)]
    [InlineData("trailing-key", false)]
    [InlineData("short-signature", false)]
    [InlineData("empty", false)]
    [InlineData("oversized", false)]
    [InlineData("wrong-curve", false)]
    public void Exact_Manifest_Requires_Provisioned_Key(string change, bool expected)
    {
        using var signer = ECDsa.Create(change == "wrong-curve"
            ? ECCurve.NamedCurves.nistP384 : ECCurve.NamedCurves.nistP256);
        using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        byte[] manifest = new byte[] { 1, 2, 3 };
        byte[] signature = signer.SignData(manifest, HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        byte[] key = (change == "wrong-key" ? other : signer).ExportSubjectPublicKeyInfo();
        if (change == "modified") manifest[0] = 4;
        if (change == "trailing-key") Array.Resize(ref key, key.Length + 1);
        if (change == "short-signature") Array.Resize(ref signature, 63);
        if (change == "empty") manifest = Array.Empty<byte>();
        if (change == "oversized") manifest = new byte[16385];
        Assert.Equal(expected, ReviewedDnsReviewSignature.Matches(manifest, signature, key));
    }
}
