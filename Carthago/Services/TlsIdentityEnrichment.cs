// SPDX-License-Identifier: MIT
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Formats.Asn1;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Carthago.Models;

namespace Carthago.Services;

internal static class TlsIdentityEnrichment
{
    internal sealed record Negotiation(string Version, string? Alpn);
    private static ushort U16(ReadOnlySpan<byte> b, int p) => BinaryPrimitives.ReadUInt16BigEndian(b.Slice(p, 2));

    // ServerHello, not ClientHello legacy_version, establishes the selected version.
    // Only cleartext ServerHello ALPN is observed (TLS 1.3 ALPN is encrypted).
    internal static bool TryReadServerHello(ReadOnlySpan<byte> record, out Negotiation result)
    {
        result = null!;
        if (record.Length < 9 || record[0] != 22 || record[5] != 2) return false;
        int recordLength = U16(record, 3);
        int length = (record[6] << 16) | (record[7] << 8) | record[8];
        if (recordLength < length + 4 || recordLength > record.Length - 5 || length < 38) return false;
        var body = record.Slice(9, length);
        // TLS 1.3 HelloRetryRequest is not a final ServerHello.
        if (body.Slice(2, 32).SequenceEqual(Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"))) return false;
        ushort version = U16(body, 0);
        int sid = body[34];
        int p = 35 + sid;
        if (sid > 32 || p > body.Length - 3) return false;
        p += 2; // selected cipher
        if (body[p++] != 0) return false;
        string? alpn = null;
        var seen = new HashSet<ushort>();
        if (p != body.Length)
        {
            if (p > body.Length - 2) return false;
            int extLen = U16(body, p); p += 2;
            if (extLen != body.Length - p) return false;
            while (p < body.Length)
            {
                if (p > body.Length - 4) return false;
                ushort type = U16(body, p); int len = U16(body, p + 2); p += 4;
                if (len > body.Length - p || !seen.Add(type)) return false;
                var ext = body.Slice(p, len); p += len;
                if (type == 43)
                {
                    if (len != 2 || version != 0x0303) return false;
                    version = U16(ext, 0);
                    if (version != 0x0304) return false;
                }
                else if (type == 16)
                {
                    if (len < 4 || U16(ext, 0) != len - 2 || ext[2] == 0 || ext[2] != len - 3) return false;
                    foreach (byte value in ext.Slice(3))
                        if (value < 0x21 || value > 0x7e) return false;
                    alpn = Encoding.ASCII.GetString(ext.Slice(3));
                }
            }
        }
        if (version == 0x0304 && alpn is not null) return false;
        string? label = version switch { 0x0301 => "TLS1.0", 0x0302 => "TLS1.1", 0x0303 => "TLS1.2", 0x0304 => "TLS1.3", _ => null };
        if (label is null || version == 0x0304 && !seen.Contains(43)) return false;
        result = new(label, alpn);
        return true;
    }

    internal static void ApplyCertificate(TrafficRecord record, X509Certificate2 cert)
    {
        record.TlsCertificateSha256 = Convert.ToHexString(SHA256.HashData(cert.RawData)).ToLowerInvariant();
        record.TlsCertificateValidityStatus = Validity(cert.NotBefore.ToUniversalTime(), cert.NotAfter.ToUniversalTime(), DateTime.UtcNow);
        try
        {
            var names = new SortedSet<string>(StringComparer.Ordinal);
            var san = cert.Extensions["2.5.29.17"];
            if (san is not null)
            {
                var reader = new AsnReader(san.RawData, AsnEncodingRules.DER);
                var seq = reader.ReadSequence();
                var dnsTag = new Asn1Tag(TagClass.ContextSpecific, 2);
                while (seq.HasData)
                {
                    if (seq.PeekTag().HasSameClassAndValue(dnsTag))
                    {
                        var name = seq.ReadCharacterString(UniversalTagNumber.IA5String, dnsTag);
                        if (NormalizeDns(name, true) is string safe) names.Add(safe);
                    }
                    else seq.ReadEncodedValue();
                }
                reader.ThrowIfNotEmpty();
            }
            record.TlsCertificateDnsNames = names.Count == 0 ? null : string.Join("; ", names);
            record.TlsCertificateNameStatus = names.Count == 0 ? "NoDnsSan" : "DnsSanObserved";
        }
        catch (AsnContentException) { record.TlsCertificateNameStatus = "MalformedSan"; }
    }

    internal static string Validity(DateTime from, DateTime to, DateTime now)
        => from > to ? "InvalidInterval" : now < from ? "NotYetValid" : now > to ? "Expired" : "WithinValidityPeriod";

    internal static string MatchName(string? sni, string? names, string? status)
    {
        if (NormalizeDns(sni, false) is not string host) return "SniUnavailable";
        if (status != "DnsSanObserved" || string.IsNullOrEmpty(names)) return "DnsSanUnavailable";
        foreach (var name in names.Split("; ", StringSplitOptions.RemoveEmptyEntries))
        {
            if (string.Equals(host, name, StringComparison.Ordinal)) return "MatchesDnsSan";
            if (name.StartsWith("*.", StringComparison.Ordinal))
            {
                int dot = host.IndexOf('.');
                if (dot > 0 && host[(dot + 1)..] == name[2..]) return "MatchesDnsSan";
            }
        }
        return "DoesNotMatchDnsSan";
    }

    private static string? NormalizeDns(string? value, bool wildcard)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        string name = value.TrimEnd('.').ToLowerInvariant();
        if (name.Length > 253 || IPAddress.TryParse(name, out _)) return null;
        var labels = name.Split('.');
        if (labels.Length < 2) return null;
        for (int i = 0; i < labels.Length; i++)
        {
            string label = labels[i];
            if (wildcard && i == 0 && label == "*" && labels.Length >= 3) continue;
            if (label.Length is < 1 or > 63 || label[0] == '-' || label[^1] == '-') return null;
            foreach (char c in label)
                if (!(c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')) return null;
        }
        return name;
    }
}
