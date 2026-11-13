// SPDX-License-Identifier: MIT
using System;
using System.Security.Cryptography;
using System.Text.Json;
using Carthago.Services.Baseline;
using Xunit;

namespace Carthago.Tests;

public sealed class ReviewedDnsManifestBindingTests
{
    private static string Digest(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes));

    [Theory]
    [InlineData("valid", true)]
    [InlineData("scope", false)]
    [InlineData("capture", false)]
    [InlineData("manifest", false)]
    [InlineData("interval", false)]
    [InlineData("classification", false)]
    [InlineData("duplicate", false)]
    [InlineData("review", false)]
    [InlineData("missing-start-offset", false)]
    [InlineData("missing-end-offset", false)]
    [InlineData("explicit-z", true)]
    [InlineData("nonzero-offset", false)]
    public void Manifest_Binds_Exact_Bytes_Scope_And_Interval(string change, bool expected)
    {
        byte[] capture = { 1, 2, 3 };
        var scope = QualifiedDnsScope.Create("192.0.2.1", "sensor", "interface", "network");
        var start = new DateTimeOffset(2026, 11, 13, 10, 0, 0, TimeSpan.Zero);
        var end = start.AddMinutes(1);
        var manifest = JsonSerializer.Serialize(new {
            version = 1, scope = scope.Subject, captureSha256 = Digest(capture),
            startUtc = change == "missing-start-offset" ? "2026-11-13T10:00:00" :
                change == "explicit-z" ? "2026-11-13T10:00:00Z" :
                change == "nonzero-offset" ? "2026-11-13T11:00:00+01:00" : start.ToString("O"),
            endUtc = change == "missing-end-offset" ? "2026-11-13T10:01:00" : end.ToString("O"),
            classification = change == "classification" ? "synthetic" : "reviewed-benign",
            reviewId = change == "review" ? "" : "review-1"
        });
        if (change == "duplicate") manifest = manifest.Insert(1, "\"version\":1,");
        byte[] bytes = System.Text.Encoding.UTF8.GetBytes(manifest);
        string digest = Digest(bytes);
        if (change == "scope") scope = QualifiedDnsScope.Create("192.0.2.1", "sensor", "other", "network");
        if (change == "capture") capture[0] = 9;
        if (change == "manifest") bytes[0] = 32;
        Assert.Equal(expected, ReviewedDnsManifestBinding.Matches(bytes, digest, capture,
            scope, start, change == "interval" ? end.AddSeconds(1) : end));
    }
}
