// SPDX-License-Identifier: MIT
namespace Carthago.Engine.Rules.Expansion;

/// <summary>Canonical R598 request observation; instance-owned cooldown.</summary>
internal sealed class PortableR598Detector
{
    private readonly WebSignatureCooldown _cooldown = new();

    internal WebSignatureObservation Evaluate(PacketEvaluationContext context, out string method)
    {
        ArgumentNullException.ThrowIfNull(context);
        var record = context.Record;
        if (!WebSignatureRequestEvidence.TryGet(record, out method, out var uri)
            || !SignatureMatches(method, uri, record.HttpUserAgent, record.HttpRequestHeaders))
            return WebSignatureObservation.None;
        return _cooldown.Observe(record.Source!, record.Destination!, record.Id, context.TimestampUtc);
    }

    private static bool SignatureMatches(string method, string uri, string? userAgent, string? headers)
    {
        var mark = uri.IndexOf('?');
        var path = mark >= 0 ? uri.Substring(0, mark) : uri;
        var query = mark >= 0 ? uri.Substring(mark + 1) : string.Empty;
        return query.Contains("=C:/Users", StringComparison.OrdinalIgnoreCase)
            || query.Contains("=C:/Program%20Files", StringComparison.OrdinalIgnoreCase)
            || query.Contains("=C:/Windows", StringComparison.OrdinalIgnoreCase)
            || query.Contains("=C%3A%5CUsers", StringComparison.OrdinalIgnoreCase)
            || query.Contains("=C%3A%5CProgram%20Files", StringComparison.OrdinalIgnoreCase)
            || query.Contains("=C%3A%5CWindows", StringComparison.OrdinalIgnoreCase);
    }
}
