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

namespace Carthago.Services.Sensors;

// Configuration only: never an execution authorization, credential or job state.
internal sealed record SavedActiveSensorProfile
{
    public string Id { get; set; } = "";
    public int Version { get; set; } = 1;
    public string AdapterId { get; set; } = "";
    public string Source { get; set; } = "";
    public string Mask { get; set; } = "";
    public string Target { get; set; } = "";
    public string Sensor { get; set; } = "";
    public string HostName { get; set; } = "";
    public int Port { get; set; }
    public int IntervalMinutes { get; set; }
    public bool SaveHistory { get; set; }

    [BsonIgnore]
    public string Label => $"{Sensor} {Target} {HostName} {Port} | {IntervalMinutes} min | {Source}/{Mask} | history: {SaveHistory}";

    internal static SavedActiveSensorProfile From(ActiveSensorProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);
        var p = ActiveSensorProfile.Create(profile.AdapterId, profile.Adapter, profile.Target,
            profile.Kind, profile.HostName, profile.Port, profile.Interval, profile.SaveHistory);
        if (profile.Id == Guid.Empty || profile.HostName != p.HostName || profile.Port != p.Port ||
            profile.Interval.Ticks % TimeSpan.TicksPerMinute != 0)
            throw new ArgumentException("Invalid saved configuration.");
        var row = new SavedActiveSensorProfile
        {
            AdapterId = p.AdapterId.ToString("D"), Source = p.Adapter.Address.ToString(),
            Mask = p.Adapter.Mask.ToString(), Target = p.Target.ToString(), Sensor = p.Kind.ToString(),
            HostName = p.HostName, Port = p.Port, IntervalMinutes = (int)p.Interval.TotalMinutes,
            SaveHistory = p.SaveHistory
        };
        row.Id = Key(row);
        if (!row.TryValidate(out _)) throw new ArgumentException("Invalid saved configuration.");
        return row;
    }

    private static string Key(SavedActiveSensorProfile row) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(new[]
        {
            row.AdapterId, row.Source, row.Mask, row.Target, row.Sensor, row.HostName,
            row.Port.ToString(System.Globalization.CultureInfo.InvariantCulture)
        })))).ToLowerInvariant();

    private static bool CanonicalIpv4(string value, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (!IPAddress.TryParse(value, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetwork ||
            parsed.ToString() != value) return false;
        ip = parsed;
        return true;
    }

    private static bool ContiguousMask(IPAddress mask)
    {
        uint bits = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(mask.GetAddressBytes());
        uint inverse = ~bits;
        return bits != 0 && (inverse & (inverse + 1)) == 0;
    }

    internal bool TryValidate(out ActiveSensorProfile? profile)
    {
        profile = null;
        if (Version != 1 || !Guid.TryParseExact(AdapterId, "D", out var adapterId) ||
            adapterId == Guid.Empty || adapterId.ToString("D") != AdapterId ||
            !CanonicalIpv4(Source, out var source) || !CanonicalIpv4(Mask, out var mask) ||
            !ContiguousMask(mask) || !CanonicalIpv4(Target, out var target) ||
            !Enum.TryParse<ActiveSensorKind>(Sensor, out var kind) || kind.ToString() != Sensor ||
            HostName is null || HostName.Length > 253 || IntervalMinutes is < 5 or > 1440 ||
            Id != Key(this)) return false;
        try
        {
            var candidate = ActiveSensorProfile.Create(adapterId, new LocalLanInterface("saved configuration", source, mask),
                target, kind, HostName, Port, TimeSpan.FromMinutes(IntervalMinutes), SaveHistory);
            if (candidate.HostName != HostName || candidate.Port != Port) return false;
            profile = candidate;
            return true;
        }
        catch (ArgumentException) { return false; }
    }

    // Called only after the operator explicitly approves this configuration.
    // The caller supplies the currently selected and resolved live scope.
    internal ActiveSensorProfile ApproveForSession(Guid adapterId, LocalLanInterface adapter, IPAddress target)
    {
        if (!TryValidate(out var candidate) || candidate is null ||
            candidate.AdapterId != adapterId || !candidate.Adapter.Address.Equals(adapter.Address) ||
            !candidate.Adapter.Mask.Equals(adapter.Mask) || !candidate.Target.Equals(target))
            throw new ArgumentException("Saved scope differs from the selected live scope. Create a new profile.");
        return ActiveSensorProfile.Create(adapterId, adapter, target, candidate.Kind, candidate.HostName,
            candidate.Port, candidate.Interval, candidate.SaveHistory);
    }
}

internal sealed record SavedActiveProfileRead(IReadOnlyList<SavedActiveSensorProfile> Rows, string? Error);

internal sealed class ActiveSensorProfileStore
{
    internal const int MaxSavedProfiles = 64;
    private static readonly object Gate = new();
    private readonly string _path;

    internal ActiveSensorProfileStore(string? path = null) =>
        _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Carthago", "active-sensor-profiles.db");

    private LiteDatabase Open()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        return new LiteDatabase(_path);
    }

    private static ILiteCollection<SavedActiveSensorProfile> Collection(LiteDatabase db) =>
        db.GetCollection<SavedActiveSensorProfile>("saved_active_profiles");

    internal SavedActiveProfileRead Read()
    {
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return new(Array.Empty<SavedActiveSensorProfile>(), null);
                using var db = Open();
                var rows = Collection(db);
                if (rows.Count() > MaxSavedProfiles)
                    return new(Array.Empty<SavedActiveSensorProfile>(), "Saved profile capacity exceeded.");
                var result = rows.FindAll().ToArray();
                if (result.Any(r => !r.TryValidate(out _)))
                    return new(Array.Empty<SavedActiveSensorProfile>(), "Invalid saved profile data. No profiles loaded.");
                return new(result.OrderBy(r => r.Target, StringComparer.Ordinal).ThenBy(r => r.Sensor, StringComparer.Ordinal)
                    .ThenBy(r => r.Id, StringComparer.Ordinal).ToArray(), null);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            { return new(Array.Empty<SavedActiveSensorProfile>(), "Saved profile storage unavailable."); }
        }
    }

    internal bool Save(ActiveSensorProfile profile)
    {
        lock (Gate)
        {
            try
            {
                var row = SavedActiveSensorProfile.From(profile);
                using var db = Open();
                var rows = Collection(db);
                if (!db.BeginTrans()) return false;
                try
                {
                    if (rows.Count() > MaxSavedProfiles || rows.FindAll().Any(r => !r.TryValidate(out _)) ||
                        rows.FindById(row.Id) is null && rows.Count() >= MaxSavedProfiles)
                    { db.Rollback(); return false; }
                    rows.Upsert(row);
                    return db.Commit();
                }
                catch { db.Rollback(); throw; }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
        }
    }

    internal bool Delete(string id)
    {
        if (id is not { Length: 64 } || id.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f'))) return false;
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return false;
                using var db = Open();
                return Collection(db).Delete(id);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
        }
    }
}
