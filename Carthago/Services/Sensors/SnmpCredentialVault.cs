// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using LiteDB;

namespace Carthago.Services.Sensors;

// No credentials in scope identity. Exact scope, not device authentication.
internal sealed record SnmpCredentialScope(Guid AdapterId, string Source, string Mask, string Target)
{
    internal static SnmpCredentialScope Create(Guid adapterId, LocalLanInterface adapter, IPAddress target)
    {
        if (adapterId == Guid.Empty || !LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(target))
            throw new ArgumentException("SNMP credential requires an approved local IPv4 scope.");
        var scope = new SnmpCredentialScope(adapterId, adapter.Address.ToString(), adapter.Mask.ToString(), target.ToString());
        if (!scope.Valid()) throw new ArgumentException("Invalid SNMP credential scope.");
        return scope;
    }

    internal bool Valid()
    {
        if (AdapterId == Guid.Empty || !Canonical(Source, out var source) ||
            !Canonical(Mask, out var mask) || !Canonical(Target, out var target)) return false;
        uint bits = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(mask.GetAddressBytes());
        uint inverse = ~bits;
        return bits != 0 && (inverse & (inverse + 1)) == 0 &&
            LocalLanDiscovery.PlanProbeTargets(new[] { new LocalLanInterface("vault", source, mask) }).Contains(target);
    }

    private static bool Canonical(string text, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (!IPAddress.TryParse(text, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetwork ||
            parsed.ToString() != text) return false;
        ip = parsed;
        return true;
    }

    internal string Key => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(
        $"snmp-v1|{AdapterId:D}|{Source}|{Mask}|{Target}|161"))).ToLowerInvariant();

    internal byte[] Entropy(Guid generation) => SHA256.HashData(Encoding.UTF8.GetBytes(
        $"Carthago.SnmpCredential.v1|{Key}|{generation:D}"));
}

// Deliberately not a record: generated ToString must never expose secrets.
internal sealed class SnmpCredential
{
    internal string User { get; }
    internal string Authentication { get; }
    internal string Privacy { get; }
    internal SnmpCredential(string user, string authentication, string privacy)
    {
        SnmpInfrastructureSensor.ValidateCredentials(user, authentication, privacy);
        User = user; Authentication = authentication; Privacy = privacy;
    }
    public override string ToString() => "[SNMP credential redacted]";
}

internal sealed class SnmpCredentialVault
{
    internal const int MaxCredentials = 64;
    private static readonly object Gate = new();
    private readonly string _path;
    internal SnmpCredentialVault(string? path = null) =>
        _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Carthago", "snmp-credentials.db");

    internal sealed class Entry
    {
        public string Id { get; set; } = "";
        public int Version { get; set; } = 1;
        public Guid Generation { get; set; }
        public byte[] ProtectedPayload { get; set; } = Array.Empty<byte>();
    }

    private LiteDatabase Open()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        return new LiteDatabase(_path);
    }
    private static ILiteCollection<Entry> Entries(LiteDatabase db) => db.GetCollection<Entry>("snmp_credentials");

    private static bool ValidEntry(Entry? row, SnmpCredentialScope scope) =>
        row is not null && row.Version == 1 && row.Id == scope.Key &&
        row.Generation != Guid.Empty && row.ProtectedPayload is { Length: > 0 and <= 8192 };

    // Fixed bounded ASCII payload; no JSON serialization of the secret object.
    private static byte[] Pack(SnmpCredential secret)
    {
        var bytes = new byte[3 + secret.User.Length + secret.Authentication.Length + secret.Privacy.Length];
        bytes[0] = (byte)secret.User.Length; bytes[1] = (byte)secret.Authentication.Length; bytes[2] = (byte)secret.Privacy.Length;
        int offset = 3;
        offset += Encoding.ASCII.GetBytes(secret.User.AsSpan(), bytes.AsSpan(offset));
        offset += Encoding.ASCII.GetBytes(secret.Authentication.AsSpan(), bytes.AsSpan(offset));
        Encoding.ASCII.GetBytes(secret.Privacy.AsSpan(), bytes.AsSpan(offset));
        return bytes;
    }

    private static SnmpCredential? Unpack(byte[] bytes)
    {
        if (bytes.Length < 3 || bytes[0] is < 1 or > 32 || bytes[1] is < 8 or > 128 ||
            bytes[2] is < 8 or > 128 || bytes.Length != 3 + bytes[0] + bytes[1] + bytes[2] ||
            bytes.Skip(3).Any(b => b > 126 || b < 32)) return null;
        return new SnmpCredential(Encoding.ASCII.GetString(bytes, 3, bytes[0]),
            Encoding.ASCII.GetString(bytes, 3 + bytes[0], bytes[1]),
            Encoding.ASCII.GetString(bytes, 3 + bytes[0] + bytes[1], bytes[2]));
    }

    internal Guid? Save(SnmpCredentialScope scope, SnmpCredential secret)
    {
        if (!scope.Valid()) return null;
        byte[]? plain = null;
        lock (Gate)
        {
            try
            {
                plain = Pack(secret);
                var generation = Guid.NewGuid();
                var protectedPayload = ProtectedData.Protect(plain, scope.Entropy(generation), DataProtectionScope.CurrentUser);
                using var db = Open();
                var rows = Entries(db);
                if (!db.BeginTrans()) return null;
                try
                {
                    if (rows.Count() > MaxCredentials || rows.FindById(scope.Key) is null && rows.Count() >= MaxCredentials)
                    { db.Rollback(); return null; }
                    rows.Upsert(new Entry { Id = scope.Key, Generation = generation, ProtectedPayload = protectedPayload });
                    return db.Commit() ? generation : null;
                }
                catch { db.Rollback(); throw; }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
            finally { if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
        }
    }

    // Metadata only: no decrypt on listing; not proof the secret can decrypt.
    internal Guid? GetGeneration(SnmpCredentialScope scope)
    {
        if (!scope.Valid()) return null;
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return null;
                using var db = Open();
                var row = Entries(db).FindById(scope.Key);
                return ValidEntry(row, scope) ? row!.Generation : null;
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
        }
    }

    internal SnmpCredential? Load(SnmpCredentialScope scope, Guid expectedGeneration)
    {
        if (!scope.Valid() || expectedGeneration == Guid.Empty) return null;
        byte[]? plain = null;
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return null;
                using var db = Open();
                var row = Entries(db).FindById(scope.Key);
                if (!ValidEntry(row, scope) || row!.Generation != expectedGeneration) return null;
                plain = ProtectedData.Unprotect(row.ProtectedPayload, scope.Entropy(row.Generation), DataProtectionScope.CurrentUser);
                return Unpack(plain);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return null; }
            finally { if (plain is not null) CryptographicOperations.ZeroMemory(plain); }
        }
    }

    internal bool Delete(SnmpCredentialScope scope)
    {
        if (!scope.Valid()) return false;
        lock (Gate)
        {
            try
            {
                if (!File.Exists(_path)) return false;
                using var db = Open();
                return Entries(db).Delete(scope.Key);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException) { return false; }
        }
    }
}
