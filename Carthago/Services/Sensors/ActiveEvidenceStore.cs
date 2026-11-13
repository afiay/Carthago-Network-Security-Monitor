// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LiteDB;
using Carthago.Engine;

namespace Carthago.Services.Sensors;

internal enum ActiveSensorKind { Tcp, Dns, Tls, Http, Gateway, Snmp }

// Separate active-probe evidence; never a TrafficRecord, detection or approved baseline.
// Public properties support LiteDB mapping; only typed projection factories create rows.
internal sealed class ActiveEvidenceRow
{
    public Guid Id { get; set; }
    public int Version { get; set; } = 1;
    public string Origin { get; set; } = "ActiveProbe";
    public string Sensor { get; set; } = "";
    public string AdapterId { get; set; } = "";
    public string Source { get; set; } = "";
    public string Target { get; set; } = "";
    public string ProbeKey { get; set; } = "";
    public string Status { get; set; } = "";
    public long ObservedTicks { get; set; }
    public string EvidenceJson { get; set; } = "";
}

internal static class ActiveEvidenceProjection
{
    private static string Hash(string value) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    private static string? HashOptional(string? value) => value is null ? null : Hash(value);

    private static ActiveEvidenceRow Row(Guid adapter, IPAddress source, IPAddress target,
        ActiveSensorKind sensor, string key, string status, DateTimeOffset observed, object evidence) =>
        new()
        {
            Id = Guid.NewGuid(), AdapterId = adapter.ToString("D"), Source = source.ToString(),
            Target = target.ToString(), Sensor = sensor.ToString(), ProbeKey = key, Status = status,
            ObservedTicks = observed.UtcDateTime.Ticks, EvidenceJson = JsonSerializer.Serialize(evidence)
        };

    internal static ActiveEvidenceRow From(Guid adapter, IReadOnlyList<TcpExposureObservation> values)
    {
        if (values.Count != TcpExposureSensor.DefaultPorts.Count ||
            !values.Select(v => v.Port).SequenceEqual(TcpExposureSensor.DefaultPorts) ||
            values.Any(v => !v.Source.Equals(values[0].Source) || !v.Target.Equals(values[0].Target)))
            throw new ArgumentException("Expected one complete TCP exposure scan.");
        return Row(adapter, values[0].Source, values[0].Target, ActiveSensorKind.Tcp, "fixed-ports-v1",
            "Completed", values.Max(v => v.ObservedUtc), new
            {
                Ports = values.Select(v => new { v.Port, Status = v.Status.ToString(),
                    DurationMs = v.Duration.TotalMilliseconds, SocketError = v.SocketError?.ToString() }).ToArray()
            });
    }

    internal static ActiveEvidenceRow From(Guid adapter, DnsIntegrityObservation v) =>
        Row(adapter, v.Source, v.Resolver, ActiveSensorKind.Dns, v.Name, v.Status.ToString(), v.ObservedUtc,
            new { v.Addresses, v.ResponseCode, DurationMs = v.Duration.TotalMilliseconds, SocketError = v.SocketError?.ToString() });

    private static object? Certificate(TlsCertificateEvidence? c) => c is null ? null : new
    {
        c.Sha256, c.NotBeforeUtc, c.NotAfterUtc, c.Validity, PolicyErrors = c.PolicyErrors.ToString(),
        ChainErrors = c.ChainErrors.Select(e => e.ToString()).ToArray(), c.FingerprintMatches
    };

    internal static ActiveEvidenceRow From(Guid adapter, TlsInspectionObservation v) =>
        Row(adapter, v.Source, v.Target, ActiveSensorKind.Tls, $"{v.HostName}:{v.Port}", v.Status.ToString(), v.ObservedUtc,
            new { v.Port, v.Protocol, v.CipherSuite, Certificate = Certificate(v.Certificate), DurationMs = v.Duration.TotalMilliseconds });

    internal static ActiveEvidenceRow From(Guid adapter, HttpHealthObservation v) =>
        Row(adapter, v.Source, v.Target, ActiveSensorKind.Http, $"{(v.Https ? "https" : "http")}://{v.HostName}:{v.Port}",
            v.Status.ToString(), v.ObservedUtc, new
            {
                v.StatusCode, Redirect = v.Redirect.ToString(), Certificate = Certificate(v.Certificate),
                Headers = v.Headers.Select(h => new { h.Name, ValueHashes = h.Values.Select(Hash).ToArray() }).ToArray(),
                DurationMs = v.Duration.TotalMilliseconds
            });

    internal static ActiveEvidenceRow From(Guid adapter, GatewayIntegrityObservation v) =>
        Row(adapter, v.Source, v.Gateway, ActiveSensorKind.Gateway, "arp", v.Status.ToString(), v.ObservedUtc,
            new { v.DirectMacs, v.CachedMac, v.CacheDiffers, v.ClaimLimitReached });

    internal static ActiveEvidenceRow From(Guid adapter, SnmpInfrastructureObservation v) =>
        Row(adapter, v.Source, v.Target, ActiveSensorKind.Snmp, "udp:161/sys-scalars-v1", v.Status.ToString(), v.ObservedUtc,
            new { NameHash = HashOptional(v.Evidence?.Name), DescriptionHash = HashOptional(v.Evidence?.Description),
                ObjectId = v.Evidence?.ObjectId, UptimeCentiseconds = v.Evidence?.UptimeCentiseconds, InterfaceCount = v.Evidence?.InterfaceCount,
                DurationMs = v.Duration.TotalMilliseconds });
}

internal sealed record ActiveEvidenceRead(IReadOnlyList<ActiveEvidenceRow> Rows, string? Error);

internal sealed class ActiveEvidenceStore
{
    internal const int MaxRows = 5000;
    internal const int MaxPayloadBytes = 16 * 1024;
    internal const int MaxQuery = 200;
    internal static readonly TimeSpan Retention = TimeSpan.FromDays(30);
    private static readonly object Gate = new();
    private readonly string _path;
    private readonly int _capacity;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Action? _beforeObservationCommit;

    internal ActiveEvidenceStore(string? path = null, int capacity = MaxRows, Func<DateTimeOffset>? clock = null,
        Action? beforeObservationCommit = null)
    {
        if (capacity is < 1 or > MaxRows) throw new ArgumentOutOfRangeException(nameof(capacity));
        _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Carthago", "active-evidence.db");
        _capacity = capacity;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _beforeObservationCommit = beforeObservationCommit;
    }

    private LiteDatabase Open()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        return new LiteDatabase(_path);
    }

    private static ILiteCollection<ActiveEvidenceRow> Collection(LiteDatabase db)
    {
        var rows = db.GetCollection<ActiveEvidenceRow>("active_observations");
        rows.EnsureIndex(x => x.ObservedTicks);
        rows.EnsureIndex(x => x.Target);
        rows.EnsureIndex(x => x.Sensor);
        return rows;
    }

    private static bool ValidAddress(string value) =>
        IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
        LocalLanDiscovery.IsLocalHostAddress(ip) && value == ip.ToString();

    private static bool ValidStatus(string sensor, string status) => sensor switch
    {
        "Tcp" => status == "Completed",
        "Dns" => Enum.TryParse<DnsIntegrityStatus>(status, out var dns) && Enum.IsDefined(dns) && dns.ToString() == status,
        "Tls" => Enum.TryParse<TlsInspectionStatus>(status, out var tls) && Enum.IsDefined(tls) && tls.ToString() == status,
        "Http" => Enum.TryParse<HttpHealthStatus>(status, out var http) && Enum.IsDefined(http) && http.ToString() == status,
        "Gateway" => Enum.TryParse<GatewayIntegrityStatus>(status, out var gateway) && Enum.IsDefined(gateway) && gateway.ToString() == status,
        "Snmp" => Enum.TryParse<SnmpInfrastructureStatus>(status, out var snmp) && Enum.IsDefined(snmp) && snmp.ToString() == status,
        _ => false
    };

    // JsonElement.TryGetProperty uses the last duplicate property. Reject
    // ambiguous objects at every nesting level instead of interpreting them.
    internal static bool UnambiguousJson(JsonElement value)
    {
        if (value.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
                if (!names.Add(property.Name) || !UnambiguousJson(property.Value)) return false;
        }
        else if (value.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in value.EnumerateArray())
                if (!UnambiguousJson(item)) return false;
        }
        return true;
    }

    private static bool Valid(ActiveEvidenceRow row, DateTimeOffset now)
    {
        if (row.Id == Guid.Empty || row.Version != 1 || row.Origin != "ActiveProbe" ||
            !Enum.TryParse<ActiveSensorKind>(row.Sensor, out var kind) || !Enum.IsDefined(kind) || kind.ToString() != row.Sensor ||
            !Guid.TryParseExact(row.AdapterId, "D", out var adapter) || adapter == Guid.Empty ||
            !ValidAddress(row.Source) || !ValidAddress(row.Target) || row.Source == row.Target ||
            string.IsNullOrWhiteSpace(row.ProbeKey) || row.ProbeKey.Length > 512 ||
            string.IsNullOrWhiteSpace(row.Status) || row.Status.Length > 64 || !ValidStatus(row.Sensor, row.Status) ||
            row.ObservedTicks < (now - Retention).UtcDateTime.Ticks ||
            row.ObservedTicks > now.UtcDateTime.Ticks ||
            string.IsNullOrWhiteSpace(row.EvidenceJson) || Encoding.UTF8.GetByteCount(row.EvidenceJson) > MaxPayloadBytes)
            return false;
        try
        {
            using var json = JsonDocument.Parse(row.EvidenceJson);
            return json.RootElement.ValueKind == JsonValueKind.Object && UnambiguousJson(json.RootElement);
        }
        catch (JsonException) { return false; }
    }

    private void Prune(ILiteCollection<ActiveEvidenceRow> rows, DateTimeOffset now)
    {
        long cutoff = (now - Retention).UtcDateTime.Ticks;
        rows.DeleteMany(x => x.ObservedTicks < cutoff);
        int excess = rows.Count() - _capacity;
        if (excess > 0)
            foreach (var stale in rows.Query().OrderBy(x => x.ObservedTicks).Limit(excess).ToList())
                rows.Delete(stale.Id);
    }

    internal bool Save(ActiveEvidenceRow row)
    {
        lock (Gate)
        {
            try
            {
                var now = _clock();
                if (!Valid(row, now)) return false;
                using var db = Open();
                var rows = Collection(db);
                var findings = Findings(db);
                if (!db.BeginTrans()) return false;
                try
                {
                    // Insert, not upsert: a reused observation ID cannot rewrite history.
                    if (rows.FindById(row.Id) is not null) { db.Rollback(); return false; }
                    // A late arrival could retroactively contradict a persisted
                    // two-observation confirmation. Live history is append-only
                    // in event time within each exact scope, not across scopes.
                    if (rows.Find(x => x.Target == row.Target).Any(previous =>
                        ActiveChangeDetector.SameScope(previous, row) && previous.ObservedTicks >= row.ObservedTicks))
                    { db.Rollback(); return false; }
                    rows.Insert(row);
                    Prune(rows, now);
                    // A backdated insert outside the retained newest set is not a successful save.
                    if (rows.FindById(row.Id) is null) { db.Rollback(); return false; }
                    EvaluateLatest(db, rows, findings, row, now);
                    // Test-only failure injection after all writes, before durable commit.
                    _beforeObservationCommit?.Invoke();
                    if (!db.Commit()) return false;
                    return true;
                }
                catch { db.Rollback(); throw; }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
        }
    }

    internal ActiveEvidenceRead Read(ActiveSensorKind? sensor = null, string? target = null, int limit = MaxQuery)
    {
        if (limit is < 1 or > MaxQuery || (sensor.HasValue && !Enum.IsDefined(sensor.Value)) ||
            (target is not null && !ValidAddress(target)))
            return new(Array.Empty<ActiveEvidenceRow>(), "Invalid history filter.");
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return new(Array.Empty<ActiveEvidenceRow>(), null);
                var now = _clock();
                using var db = Open();
                var rows = Collection(db);
                db.BeginTrans();
                try { Prune(rows, now); db.Commit(); }
                catch { db.Rollback(); throw; }
                // Bounded retained population; exact filters before limiting, stable tie ordering.
                var all = rows.Query().OrderByDescending(x => x.ObservedTicks).Limit(MaxRows).ToList();
                var matched = all.Where(r => (sensor is null || r.Sensor == sensor.Value.ToString()) &&
                    (target is null || r.Target == target)).ToArray();
                var valid = matched.Where(r => Valid(r, now)).OrderByDescending(r => r.ObservedTicks)
                    .ThenBy(r => r.Id).Take(limit).ToArray();
                return new(valid, matched.Any(r => !Valid(r, now)) ? "Invalid history entries skipped." : null);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { return new(Array.Empty<ActiveEvidenceRow>(), "Active evidence history unavailable."); }
        }
    }

    // Approval references a retained row; never silently advances or copies evidence.
    internal sealed class Approval
    {
        public string Id { get; set; } = "";
        public Guid ObservationId { get; set; }
        public long ApprovedTicks { get; set; }
    }
    internal const int MaxApprovals = 128;
    private static string ScopeKey(ActiveEvidenceRow row) => Convert.ToHexString(SHA256.HashData(
        Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new[] { row.Sensor, row.AdapterId, row.Source, row.Target, row.ProbeKey }))));

    internal bool Approve(Guid observationId)
    {
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return false;
                using var db = Open();
                var rows = Collection(db);
                var approvals = db.GetCollection<Approval>("active_approved_baselines");
                var now = _clock();
                db.BeginTrans();
                try
                {
                    Prune(rows, now);
                    var row = rows.FindById(observationId);
                    if (row is null || !Valid(row, now) || !ActiveChangeDetector.EligibleBaseline(row))
                    { db.Rollback(); return false; }
                    foreach (var old in approvals.FindAll().ToArray())
                        if (rows.FindById(old.ObservationId) is null) approvals.Delete(old.Id);
                    var key = ScopeKey(row);
                    if (approvals.FindById(key) is null && approvals.Count() >= MaxApprovals)
                    { db.Rollback(); return false; }
                    approvals.Upsert(new Approval { Id = key, ObservationId = row.Id, ApprovedTicks = now.UtcDateTime.Ticks });
                    if (!db.Commit()) return false;
                    return true;
                }
                catch { db.Rollback(); throw; }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
        }
    }

    internal ActiveChangeResult CompareApproved(Guid currentId)
    {
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return new("Incomparable", Array.Empty<ActiveChange>(), "No saved history.");
                using var db = Open();
                var rows = Collection(db);
                var now = _clock();
                var current = rows.FindById(currentId);
                if (current is null || !Valid(current, now))
                    return new("Incomparable", Array.Empty<ActiveChange>(), "Current observation unavailable or expired.");
                var approval = db.GetCollection<Approval>("active_approved_baselines").FindById(ScopeKey(current));
                var baseline = approval is null ? null : rows.FindById(approval.ObservationId);
                if (baseline is null || !Valid(baseline, now))
                    return new("NoApprovedBaseline", Array.Empty<ActiveChange>(), "Approve a retained observation for this exact scope.");
                return ActiveChangeDetector.Compare(baseline, current);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { return new("Unavailable", Array.Empty<ActiveChange>(), "Active history comparison unavailable."); }
        }
    }

    private static ILiteCollection<ActiveFindingRow> Findings(LiteDatabase db)
    {
        var findings = db.GetCollection<ActiveFindingRow>("active_findings");
        findings.EnsureIndex(x => x.ObservedTicks);
        return findings;
    }

    private static void PruneFindings(ILiteCollection<ActiveFindingRow> findings, DateTimeOffset now)
    {
        long cutoff = (now - Retention).UtcDateTime.Ticks;
        findings.DeleteMany(x => x.ObservedTicks < cutoff);
        int excess = findings.Count() - ActiveFindingQualification.MaxFindings;
        if (excess > 0)
            foreach (var stale in findings.Query().OrderBy(x => x.ObservedTicks).Limit(excess).ToList())
                findings.Delete(stale.Id);
    }

    // Called inside the observation insert transaction. No separate delivery or
    // packet-rule side effect: observation and qualified findings commit together.
    private static void EvaluateLatest(LiteDatabase db, ILiteCollection<ActiveEvidenceRow> rows,
        ILiteCollection<ActiveFindingRow> findings, ActiveEvidenceRow current, DateTimeOffset now)
    {
        PruneFindings(findings, now);
        var approval = db.GetCollection<Approval>("active_approved_baselines").FindById(ScopeKey(current));
        if (approval is null) return;
        var baseline = rows.FindById(approval.ObservationId);
        if (baseline is null || !Valid(baseline, now) || !ActiveChangeDetector.SameScope(baseline, current)) return;
        // Use the latest two observations, not the latest two positive matches.
        // A recovery, malformed/inconclusive observation or intervening result
        // breaks the confirmation sequence. Equal timestamps are ambiguous.
        var recent = rows.Find(x => x.Target == current.Target)
            .Where(r => ActiveChangeDetector.SameScope(current, r) && r.ObservedTicks >= approval.ApprovedTicks &&
                r.ObservedTicks > baseline.ObservedTicks)
            .OrderByDescending(r => r.ObservedTicks).ThenBy(r => r.Id).Take(3).ToArray();
        if (recent.Length < 2 || recent[0].Id != current.Id ||
            (recent.Length > 2 && recent[1].ObservedTicks == recent[2].ObservedTicks) ||
            !Valid(recent[1], now)) return;
        foreach (var finding in ActiveFindingQualification.Qualify(baseline, recent[1], current, approval.ApprovedTicks, now))
            if (findings.FindById(finding.Id) is null) findings.Insert(finding);
        PruneFindings(findings, now);
    }

    internal (IReadOnlyList<ActiveFindingRow> Rows, string? Error) ReadFindings(
        ActiveSensorKind? sensor = null, string? target = null, int limit = MaxQuery)
    {
        if (limit is < 1 or > MaxQuery || (sensor.HasValue && !Enum.IsDefined(sensor.Value)) ||
            (target is not null && !ValidAddress(target)))
            return (Array.Empty<ActiveFindingRow>(), "Invalid finding filter.");
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return (Array.Empty<ActiveFindingRow>(), null);
                using var db = Open();
                var findings = Findings(db);
                var now = _clock();
                if (!db.BeginTrans()) return (Array.Empty<ActiveFindingRow>(), "Active findings transaction unavailable.");
                try
                {
                    PruneFindings(findings, now);
                    if (!db.Commit()) return (Array.Empty<ActiveFindingRow>(), "Active findings retention failed.");
                }
                catch { db.Rollback(); throw; }
                return (findings.Query().OrderByDescending(x => x.ObservedTicks).Limit(ActiveFindingQualification.MaxFindings)
                    .ToList().Where(r => (sensor is null || r.Sensor == sensor.Value.ToString()) &&
                        (target is null || r.Target == target) && r.ObservedTicks <= now.UtcDateTime.Ticks)
                    .OrderByDescending(r => r.ObservedTicks).ThenBy(r => r.Id).Take(limit).ToArray(), null);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { return (Array.Empty<ActiveFindingRow>(), "Active findings unavailable."); }
        }
    }
}
