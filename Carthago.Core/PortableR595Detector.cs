// SPDX-License-Identifier: MIT
namespace Carthago.Engine.Rules.Expansion;

/// <summary>Canonical R595 request observation; instance-owned cooldown.</summary>
internal sealed class PortableR595Detector
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
        if (!path.Contains("/public/plugins/", StringComparison.OrdinalIgnoreCase)) return false;
var pos = path.IndexOf("/public/plugins/", StringComparison.OrdinalIgnoreCase) + "/public/plugins/".Length;
var tail = path.Substring(pos);
var sep = tail.IndexOf('/');
if (sep <= 0) return false;
var plugin = tail.Substring(0, sep);
if (!IsKnownPlugin(plugin)) return false;
var count = 0;
var offset = sep;
while ((offset = tail.IndexOf("../", offset, StringComparison.Ordinal)) >= 0)
{
count++;
offset += 3;
}
return count >= 4;
    }

    private static bool IsKnownPlugin(string name)
        => name.Equals("live", StringComparison.OrdinalIgnoreCase)
        || name.Equals("loki", StringComparison.OrdinalIgnoreCase)
        || name.Equals("grafana", StringComparison.OrdinalIgnoreCase)
        || name.Equals("mysql", StringComparison.OrdinalIgnoreCase)
        || name.Equals("postgres", StringComparison.OrdinalIgnoreCase)
        || name.Equals("prometheus", StringComparison.OrdinalIgnoreCase)
        || name.Equals("graph", StringComparison.OrdinalIgnoreCase)
        || name.Equals("table", StringComparison.OrdinalIgnoreCase)
        || name.Equals("alertmanager", StringComparison.OrdinalIgnoreCase);
}
