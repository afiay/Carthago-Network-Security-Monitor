// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace Carthago.Services.Sensors;

internal sealed record ActiveChange(string Kind, string Field, string Before, string After);
internal sealed record ActiveChangeResult(string Status, IReadOnlyList<ActiveChange> Changes, string? Note = null);

internal static class ActiveChangeDetector
{
    internal static bool SameScope(ActiveEvidenceRow a, ActiveEvidenceRow b) =>
        a.Version == 1 && b.Version == 1 && a.Origin == "ActiveProbe" && b.Origin == "ActiveProbe" &&
        a.Sensor == b.Sensor && a.AdapterId == b.AdapterId && a.Source == b.Source &&
        a.Target == b.Target && a.ProbeKey == b.ProbeKey;

    internal static bool EligibleBaseline(ActiveEvidenceRow row)
    {
        try
        {
            using var doc = JsonDocument.Parse(row.EvidenceJson);
            var root = doc.RootElement;
            return row.Sensor switch
            {
                "Tcp" => row.Status == "Completed" && Ports(root).Values.Any(DefinitePort),
                "Dns" => DnsSet(row, root) is not null,
                "Tls" => row.Status == "Authenticated" && Certificate(root) is { } cert && cert.Policy == "None",
                "Http" => HttpCode(row, root) is not null,
                "Gateway" => GatewaySet(row, root) is { Length: 1 },
                "Snmp" => (row.Status is "Observed" or "Partial") && SnmpFields(root).Count > 0,
                _ => false
            };
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException) { return false; }
    }

    internal static ActiveChangeResult Compare(ActiveEvidenceRow baseline, ActiveEvidenceRow current)
    {
        if (!SameScope(baseline, current) || baseline.Id == current.Id || current.ObservedTicks <= baseline.ObservedTicks)
            return new("Incomparable", Array.Empty<ActiveChange>(), "Require same scope and a newer distinct observation.");
        if (!EligibleBaseline(baseline))
            return new("Incomparable", Array.Empty<ActiveChange>(), "Baseline lacks usable evidence.");
        var changes = new List<ActiveChange>();
        int compared = 0;
        void Field(string kind, string field, string? before, string? after)
        {
            if (before is null || after is null) return;
            compared++;
            if (before != after) changes.Add(new(kind, field, before, after));
        }
        try
        {
            using var oldDoc = JsonDocument.Parse(baseline.EvidenceJson);
            using var newDoc = JsonDocument.Parse(current.EvidenceJson);
            var a = oldDoc.RootElement; var b = newDoc.RootElement;
            switch (current.Sensor)
            {
                case "Tcp":
                    if (current.Status != "Completed") break;
                    var oldPorts = Ports(a); var newPorts = Ports(b);
                    foreach (var port in TcpExposureSensor.DefaultPorts)
                        if (oldPorts.TryGetValue(port, out var oldState) && newPorts.TryGetValue(port, out var newState)
                            && DefinitePort(oldState) && DefinitePort(newState))
                            Field(newState == "Open" ? "PortOpened" : "PortRefused", $"TCP {port}", oldState, newState);
                    break;
                case "Dns":
                    var oldDns = DnsSet(baseline, a); var newDns = DnsSet(current, b);
                    if (oldDns is not null && newDns is not null)
                        Field("DnsAnswerChanged", "IPv4 answers", string.Join(", ", oldDns), string.Join(", ", newDns));
                    break;
                case "Tls":
                    if (current.Status is not ("Authenticated" or "CertificateRejected")) break;
                    var oldCert = Certificate(a); var newCert = Certificate(b);
                    if (oldCert is not null && newCert is not null)
                    {
                        Field("CertificateChanged", "SHA-256", oldCert.Value.Hash, newCert.Value.Hash);
                        Field("CertificateValidityChanged", "Validity", oldCert.Value.Validity, newCert.Value.Validity);
                        Field("CertificatePolicyChanged", "Policy", oldCert.Value.Policy, newCert.Value.Policy);
                    }
                    break;
                case "Http":
                    var oldCode = HttpCode(baseline, a); var newCode = HttpCode(current, b);
                    if (oldCode is null || newCode is null) break;
                    Field("HttpStatusChanged", "HTTP status", oldCode.ToString(), newCode.ToString());
                    if (oldCode is >= 200 and < 300 && newCode is >= 200 and < 300)
                    {
                        var oldHeaders = Headers(a); var newHeaders = Headers(b);
                        if (oldHeaders is not null && newHeaders is not null)
                            foreach (var name in oldHeaders.Keys.Union(newHeaders.Keys).OrderBy(n => n, StringComparer.Ordinal))
                                Field("HttpHeaderChanged", name, oldHeaders.GetValueOrDefault(name, "Absent"),
                                    newHeaders.GetValueOrDefault(name, "Absent"));
                    }
                    break;
                case "Gateway":
                    var oldMacs = GatewaySet(baseline, a); var newMacs = GatewaySet(current, b);
                    if (oldMacs is not null && newMacs is not null)
                        Field(newMacs.Length > 1 ? "GatewayCompetingClaims" : "GatewayMacChanged", "Direct MAC claims",
                            string.Join(", ", oldMacs), string.Join(", ", newMacs));
                    break;
                case "Snmp":
                    if (current.Status is not ("Observed" or "Partial")) break;
                    var oldFields = SnmpFields(a); var newFields = SnmpFields(b);
                    foreach (var name in oldFields.Keys)
                        if (newFields.TryGetValue(name, out var value))
                            Field("SnmpInventoryChanged", name, oldFields[name], value);
                    break;
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or ArgumentException)
        { return new("Incomparable", Array.Empty<ActiveChange>(), "Malformed evidence."); }
        return compared == 0 ? new("Inconclusive", Array.Empty<ActiveChange>(), "No comparable positive evidence.") :
            new(changes.Count == 0 ? "NoChangeObserved" : "Changed", changes.AsReadOnly(),
                "Only comparable fields evaluated; changes are not proof of compromise.");
    }

    private static string? Text(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
    private static int? Number(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) &&
        v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out int n) ? n : null;
    private static bool Hash(string? s) => s is { Length: 64 } && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static bool DefinitePort(string status) => status is "Open" or "Refused";
    private static Dictionary<int, string> Ports(JsonElement root)
    {
        var result = new Dictionary<int, string>();
        if (!root.TryGetProperty("Ports", out var array) || array.ValueKind != JsonValueKind.Array ||
            array.GetArrayLength() != TcpExposureSensor.DefaultPorts.Count) return result;
        foreach (var v in array.EnumerateArray())
        {
            int? port = Number(v, "Port"); string? status = Text(v, "Status");
            if (!port.HasValue || !TcpExposureSensor.DefaultPorts.Contains(port.Value) ||
                status is not ("Open" or "Refused" or "TimedOut" or "Unreachable" or "Error") ||
                !result.TryAdd(port.Value, status)) return new();
        }
        return result;
    }

    private static string[]? StringSet(JsonElement root, string name, Func<string, bool> valid, int max)
    {
        if (!root.TryGetProperty(name, out var values) || values.ValueKind != JsonValueKind.Array ||
            values.GetArrayLength() > max) return null;
        var result = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var v in values.EnumerateArray())
        {
            if (v.ValueKind != JsonValueKind.String || v.GetString() is not string s || !valid(s)) return null;
            result.Add(s);
        }
        return result.ToArray();
    }

    private static string[]? DnsSet(ActiveEvidenceRow row, JsonElement root)
    {
        if (row.Status is not ("AnswersObserved" or "AnswersMatch" or "AnswersDiffer") ||
            Number(root, "ResponseCode") != 0) return null;
        var set = StringSet(root, "Addresses", s => IPAddress.TryParse(s, out var ip) &&
            ip.AddressFamily == AddressFamily.InterNetwork && ip.ToString() == s, 256);
        return set is { Length: > 0 } ? set : null;
    }

    private static (string Hash, string Validity, string Policy)? Certificate(JsonElement root)
    {
        if (!root.TryGetProperty("Certificate", out var cert) || cert.ValueKind != JsonValueKind.Object) return null;
        var hash = Text(cert, "Sha256"); var validity = Text(cert, "Validity"); var policy = Text(cert, "PolicyErrors");
        return Hash(hash) && validity is not null && policy is not null ? (hash!, validity, policy) : null;
    }

    private static int? HttpCode(ActiveEvidenceRow row, JsonElement root) =>
        row.Status == "ResponseObserved" && Number(root, "StatusCode") is int n && n is >= 200 and <= 599 ? n : null;

    private static Dictionary<string, string>? Headers(JsonElement root)
    {
        if (!root.TryGetProperty("Headers", out var array) || array.ValueKind != JsonValueKind.Array || array.GetArrayLength() > 8) return null;
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        var permitted = new[] { "Server", "Strict-Transport-Security", "Content-Security-Policy",
            "Content-Security-Policy-Report-Only", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy" };
        foreach (var item in array.EnumerateArray())
        {
            var name = Text(item, "Name");
            if (name is null || !permitted.Contains(name, StringComparer.Ordinal) ||
                !item.TryGetProperty("ValueHashes", out var hashes) || hashes.ValueKind != JsonValueKind.Array ||
                hashes.GetArrayLength() is < 1 or > 128) return null;
            var values = new List<string>();
            foreach (var h in hashes.EnumerateArray())
            {
                if (h.ValueKind != JsonValueKind.String || !Hash(h.GetString())) return null;
                values.Add(h.GetString()!);
            }
            if (!result.TryAdd(name, string.Join(", ", values))) return null;
        }
        return result;
    }

    private static string[]? GatewaySet(ActiveEvidenceRow row, JsonElement root)
    {
        if (row.Status is not ("Observed" or "BaselineMatch" or "BaselineDifference" or "ConflictingClaims")) return null;
        if (!root.TryGetProperty("ClaimLimitReached", out var limit) || limit.ValueKind != JsonValueKind.False) return null;
        var set = StringSet(root, "DirectMacs", s => GatewayIntegritySensor.NormalizeMac(s) == s, 16);
        if (set is not { Length: > 0 } || (row.Status == "ConflictingClaims") != (set.Length > 1)) return null;
        return set;
    }

    private static Dictionary<string, string> SnmpFields(JsonElement root)
    {
        var fields = new Dictionary<string, string>();
        foreach (var name in new[] { "NameHash", "DescriptionHash" })
            if (Text(root, name) is string s && Hash(s)) fields[name] = s;
        if (Text(root, "ObjectId") is string oid && oid.Length is > 0 and <= 256 && oid.All(c => c is >= '0' and <= '9' or '.'))
            fields["ObjectId"] = oid;
        if (Number(root, "InterfaceCount") is int count && count >= 0)
            fields["InterfaceCount"] = count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        return fields;
    }
}
