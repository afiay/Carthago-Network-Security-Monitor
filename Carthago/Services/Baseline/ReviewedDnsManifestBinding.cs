// SPDX-License-Identifier: MIT
using System;
using System.Text.Json;

namespace Carthago.Services.Baseline
{
    // Structural binding only. The expected manifest digest must come from an
    // independently authenticated review channel, not the capture supplier.
    // No live baseline writer consumes this result.
    internal static class ReviewedDnsManifestBinding
    {
        // DateTimeOffset parsing can interpret a missing offset using local time.
        // Require an explicit UTC designator so acceptance is host-independent.
        private static bool HasExplicitUtcOffset(string? value) =>
            value != null && (value.EndsWith("Z", StringComparison.Ordinal) ||
                value.EndsWith("+00:00", StringComparison.Ordinal));

        internal static bool Matches(ReadOnlySpan<byte> manifest, string expectedManifestSha256,
            ReadOnlySpan<byte> capture, QualifiedDnsScope scope, DateTimeOffset firstPacket,
            DateTimeOffset lastPacket)
        {
            if (manifest.Length > 16384 || scope == null ||
                !ReviewedDnsCaptureBinding.Matches(manifest, expectedManifestSha256))
                return false;
            try
            {
                using var document = JsonDocument.Parse(manifest.ToArray());
                var root = document.RootElement;
                if (root.ValueKind != JsonValueKind.Object) return false;
                var names = new System.Collections.Generic.HashSet<string>(StringComparer.Ordinal);
                foreach (var property in root.EnumerateObject())
                    if (!names.Add(property.Name)) return false;
                if (names.Count != 7) return false;
                if (!root.TryGetProperty("version", out var version) ||
                    version.ValueKind != JsonValueKind.Number ||
                    !version.TryGetInt32(out var v) || v != 1) return false;
                string? Read(string name) => root.TryGetProperty(name, out var value) &&
                    value.ValueKind == JsonValueKind.String ? value.GetString() : null;
                var review = Read("reviewId");
                if (string.IsNullOrWhiteSpace(review) || review.Length > 256 ||
                    review != review.Trim() || Read("classification") != "reviewed-benign" ||
                    Read("scope") != scope.Subject) return false;
                if (!root.TryGetProperty("startUtc", out var start) ||
                    !root.TryGetProperty("endUtc", out var end) ||
                    start.ValueKind != JsonValueKind.String || end.ValueKind != JsonValueKind.String ||
                    !HasExplicitUtcOffset(start.GetString()) || !HasExplicitUtcOffset(end.GetString()) ||
                    !start.TryGetDateTimeOffset(out var from) || !end.TryGetDateTimeOffset(out var to) ||
                    from.Offset != TimeSpan.Zero || to.Offset != TimeSpan.Zero ||
                    firstPacket.Offset != TimeSpan.Zero || lastPacket.Offset != TimeSpan.Zero ||
                    from >= to || firstPacket > lastPacket || firstPacket < from || lastPacket > to)
                    return false;
                return ReviewedDnsCaptureBinding.Matches(capture, Read("captureSha256")!);
            }
            catch (JsonException) { return false; }
        }
    }
}
