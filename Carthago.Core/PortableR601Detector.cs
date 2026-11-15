// SPDX-License-Identifier: MIT
namespace Carthago.Engine.Rules.Expansion;

/// <summary>R601 request-only observation; requires complete capture-derived headers.</summary>
internal sealed class PortableR601Detector
{
    private readonly WebSignatureCooldown _cooldown = new();

    internal WebSignatureObservation Evaluate(PacketEvaluationContext context, out string method)
    {
        ArgumentNullException.ThrowIfNull(context);
        var record = context.Record;
        if (!WebSignatureRequestEvidence.TryGet(record, out method, out var uri)
            || method != "POST"
            || !record.HasBoundCompleteHttpRequestHeaders
            || record.HttpUserAgentHeaderObserved || record.HttpRefererHeaderObserved
            || !string.IsNullOrWhiteSpace(record.HttpUserAgent)
            || string.IsNullOrWhiteSpace(record.HttpRequestHeaders)
            || record.HttpRequestHeaders.Contains("Referer:", StringComparison.OrdinalIgnoreCase))
            return WebSignatureObservation.None;
        var mark = uri.IndexOf('?');
        if (mark < 0) return WebSignatureObservation.None;
        var query = uri.Substring(mark + 1);
        if (!query.Contains("cmd=read", StringComparison.OrdinalIgnoreCase)
            && !query.Contains("connect&target", StringComparison.OrdinalIgnoreCase)
            && !query.Contains("cmd=connect", StringComparison.OrdinalIgnoreCase)
            && !query.Contains("cmd=disconnect", StringComparison.OrdinalIgnoreCase)
            && !query.Contains("cmd=forward", StringComparison.OrdinalIgnoreCase))
            return WebSignatureObservation.None;
        return _cooldown.Observe(record.Source!, record.Destination!, record.Id, context.TimestampUtc);
    }
}
