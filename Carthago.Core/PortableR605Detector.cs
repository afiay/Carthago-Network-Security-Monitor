// SPDX-License-Identifier: MIT
namespace Carthago.Engine.Rules.Expansion;

internal sealed class PortableR605Detector
{
    private readonly WebSignatureCooldown _cooldown = new();
    internal WebSignatureObservation Evaluate(PacketEvaluationContext context,out string method)
    {
        ArgumentNullException.ThrowIfNull(context);
        var record=context.Record;
        if(!WebSignatureRequestEvidence.TryGet(record,out method,out var uri)
            || !SignatureMatches(method,uri,record.HttpUserAgent,record.HttpRequestHeaders))
            return WebSignatureObservation.None;
        return _cooldown.Observe(record.Source!,record.Destination!,record.Id,context.TimestampUtc);
    }

    private static bool SignatureMatches(string method, string uri, string? userAgent, string? headers)
    {
        var mark = uri.IndexOf('?');
        var path = mark >= 0 ? uri.Substring(0, mark) : uri;
        var query = mark >= 0 ? uri.Substring(mark + 1) : string.Empty;
        return string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase)
            && path.Contains("/upload.action", StringComparison.OrdinalIgnoreCase)
            && query.Contains("filename=../../../../", StringComparison.OrdinalIgnoreCase);
    }
}
