// SPDX-License-Identifier: MIT
namespace Carthago.Engine.Rules.Expansion;

internal sealed class PortableR602Detector
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
        if (!uri.Contains("/SolarWinds/", StringComparison.OrdinalIgnoreCase)
            || !uri.Contains("/api/", StringComparison.OrdinalIgnoreCase)) return false;
        if (uri.Contains("Orion/Skipi18n/Profiler/", StringComparison.OrdinalIgnoreCase)
            || uri.Contains("css.i18n.ashx", StringComparison.OrdinalIgnoreCase)
            || uri.Contains("js.i18n.ashx", StringComparison.OrdinalIgnoreCase)) return false;
        return uri.Contains("/WebResource.axd", StringComparison.OrdinalIgnoreCase)
            || uri.Contains("/ScriptResource.axd", StringComparison.OrdinalIgnoreCase)
            || uri.Contains("/i18n.ashx", StringComparison.OrdinalIgnoreCase)
            || uri.Contains("/Skipi18n", StringComparison.OrdinalIgnoreCase);
    }
}
