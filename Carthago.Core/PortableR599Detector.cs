// SPDX-License-Identifier: MIT
namespace Carthago.Engine.Rules.Expansion;

/// <summary>Canonical R599 request observation; instance-owned cooldown.</summary>
internal sealed class PortableR599Detector
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
        return path.Contains("/apply_abstract.cgi", StringComparison.OrdinalIgnoreCase)
            && uri.Contains("..%2f", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("/images/", StringComparison.OrdinalIgnoreCase)
            && !path.Contains("/css/", StringComparison.OrdinalIgnoreCase);
    }
}
