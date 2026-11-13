// SPDX-License-Identifier: MIT
namespace Carthago.Engine.Rules.Expansion;

/// <summary>Canonical R591 request observation; instance-owned cooldown.</summary>
internal sealed class PortableR591Detector
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
        return path.Contains("/ServletApi/../RestApi/LogonCustomization", StringComparison.OrdinalIgnoreCase)
|| path.Contains("/ServletApi/../RestAPI/Connection", StringComparison.OrdinalIgnoreCase)
|| path.Contains("/help/admin-guide/Reports/ReportGenerate.jsp", StringComparison.OrdinalIgnoreCase);
    }
}
