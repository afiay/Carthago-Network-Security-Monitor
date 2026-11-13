// SPDX-License-Identifier: MIT
namespace Carthago.Engine.Rules.Expansion;

/// <summary>Canonical R593 request observation; instance-owned cooldown.</summary>
internal sealed class PortableR593Detector
{
    private readonly WebSignatureCooldown _cooldown = new();

    internal WebSignatureObservation Evaluate(PacketEvaluationContext context, out string method)
    {
        ArgumentNullException.ThrowIfNull(context);
        var record = context.Record;
        if (!WebSignatureRequestEvidence.TryGet(record, out method, out var uri)
            || !SignatureMatches(method, uri))
            return WebSignatureObservation.None;
        return _cooldown.Observe(record.Source!, record.Destination!, record.Id, context.TimestampUtc);
    }

    private static bool SignatureMatches(string method, string uri)
    {
        var delimiter = uri.IndexOf('?');
        var path = delimiter >= 0 ? uri.Substring(0, delimiter) : uri;
        var query = delimiter >= 0 ? uri.Substring(delimiter + 1) : string.Empty;
        return query.Contains("doAs=`", StringComparison.OrdinalIgnoreCase)
&& (query.StartsWith("doAs=", StringComparison.OrdinalIgnoreCase)
    || query.Contains("&doAs=", StringComparison.OrdinalIgnoreCase));
    }
}
