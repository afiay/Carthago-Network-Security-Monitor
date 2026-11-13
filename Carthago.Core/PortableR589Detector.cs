// SPDX-License-Identifier: MIT
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion;

/// <summary>Canonical R589 request observation and per-session cooldown; not alert publication.</summary>
internal sealed class PortableR589Detector
{
    private readonly WebSignatureCooldown _cooldown = new();

    internal WebSignatureObservation Evaluate(PacketEvaluationContext context, out string method)
    {
        ArgumentNullException.ThrowIfNull(context);
        var record = context.Record;
        if (!WebSignatureRequestEvidence.TryGet(record, out method, out var uri)
            || !SignatureMatches(uri))
            return WebSignatureObservation.None;
        return _cooldown.Observe(record.Source!, record.Destination!, record.Id, context.TimestampUtc);
    }

    private static bool SignatureMatches(string uri)
    {
        var delimiter = uri.IndexOf('?');
        var path = delimiter >= 0 ? uri[..delimiter] : uri;
        return path.Contains("/config/keystore/", StringComparison.OrdinalIgnoreCase)
            && (path.EndsWith(".jsp", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".jspx", StringComparison.OrdinalIgnoreCase)
                || path.EndsWith(".jsf", StringComparison.OrdinalIgnoreCase));
    }
}
