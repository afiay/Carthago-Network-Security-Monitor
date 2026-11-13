// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;
using Carthago.Services.Baseline;
using Xunit;

namespace Carthago.Tests;

public sealed class ReviewedDnsCaptureBindingTests
{
    [Fact]
    public void Exact_Bytes_Match_But_Mutation_And_Truncation_Do_Not()
    {
        byte[] bytes = { 1, 2, 3, 4 };
        string digest = Convert.ToHexString(SHA256.HashData(bytes));
        Assert.True(ReviewedDnsCaptureBinding.Matches(bytes, digest));
        Assert.False(ReviewedDnsCaptureBinding.Matches(new byte[] { 1, 2, 3, 5 }, digest));
        Assert.False(ReviewedDnsCaptureBinding.Matches(bytes.AsSpan(0, 3), digest));
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-digest")]
    [InlineData(null)]
    public void Invalid_Digest_Is_Rejected(string? digest)
    {
        Assert.False(ReviewedDnsCaptureBinding.Matches(new byte[] { 1 }, digest!));
    }

    [Fact]
    public void Empty_Capture_Is_Rejected_Even_With_Matching_Digest()
    {
        Assert.False(ReviewedDnsCaptureBinding.Matches(Array.Empty<byte>(),
            Convert.ToHexString(SHA256.HashData(Array.Empty<byte>()))));
    }
}
