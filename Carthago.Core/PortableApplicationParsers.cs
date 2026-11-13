// SPDX-License-Identifier: MIT
// Existing lightweight application parsers; extracted without algorithm changes.
using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;
using Carthago.Engine.Rules;

namespace Carthago.Services
{
    internal static class HttpLight
    {
        private static readonly byte[] CRLF = new byte[] { 0x0D, 0x0A };

        internal sealed class HttpInfo
        {
            public string? Method { get; init; }
            public string? Path { get; init; }
            public string? Host { get; init; }
            public string? UserAgent { get; init; }
            public string? HttpVersion { get; init; }
            public List<string> HeaderNames { get; init; } = new();
            public string? JoinedHeaderLines { get; init; }
            public bool ObservedDefaultBasicCredential { get; init; }
            public bool ObservedGitHubTokenPattern { get; init; }
            public bool ObservedGitLabTokenPattern { get; init; }
            public bool ObservedAzureDevOpsPatUrlPattern { get; init; }
            public bool ObservedCircleCiTokenPattern { get; init; }
            public bool ObservedVaultTokenPattern { get; init; }
            public bool ObservedTerraformTokenPattern { get; init; }
            public bool ObservedNpmTokenPattern { get; init; }
            public bool ObservedPyPiUploadAuthorization { get; init; }
            public bool ObservedAwsListSecretsRequest { get; init; }
        }

        public static bool TryParseHttp(ReadOnlySpan<byte> data, out HttpInfo info)
        {
            info = new HttpInfo();
            int lineEnd = data.IndexOf(CRLF);
            if (lineEnd < 0 || lineEnd > 8192) return false;

            var firstLine = data.Slice(0, lineEnd);
            if (TryParseRequestLine(firstLine, out var method, out var path, out var vers))
            {
                info = ParseHeaders(data, lineEnd + CRLF.Length, method, path, vers);
                return true;
            }

            if (StartsWith(firstLine, "HTTP/1.") || StartsWith(firstLine, "HTTP/2"))
            {
                info = ParseHeaders(data, lineEnd + CRLF.Length, null, null, ToAscii(firstLine.Slice(0, Math.Min(8, firstLine.Length))));
                return info.Host != null || info.UserAgent != null;
            }

            return false;
        }

        private static HttpInfo ParseHeaders(ReadOnlySpan<byte> data, int offset, string? method, string? path, string? httpVersion)
        {
            string? host = null, ua = null;
            bool defaultBasicObserved = false;
            bool githubTokenObserved = false, gitlabTokenObserved = false;
            bool azurePatUrlObserved = HasAzurePatQuery(path);
            bool circleCiTokenObserved = false;
            bool vaultTokenObserved = false, terraformTokenObserved = false, npmTokenObserved = false;
            bool pypiUploadAuthorizationObserved = false, awsListSecretsObserved = false;
            int vaultHeaderCount = 0, awsTargetCount = 0;
            int circleCiHeaderCount = 0;
            int authorizationHeaderCount = 0;
            bool headerSectionComplete = false;
            int idx = offset;
            var headerNames = new List<string>();
            var sbJoin = new StringBuilder();

            while (idx < data.Length)
            {
                int end = data.Slice(idx).IndexOf(CRLF);
                if (end < 0) break;
                if (end == 0)
                {
                    headerSectionComplete = true;
                    break; // complete CRLF-terminated header section
                }

                var line = data.Slice(idx, end);
                idx += end + CRLF.Length;

                int colon = line.IndexOf((byte)':');
                if (colon > 0)
                {
                    var name = ToAscii(line.Slice(0, colon));
                    headerNames.Add(name);
                    if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                    {
                        authorizationHeaderCount++;
                        // Duplicate Authorization fields are ambiguous: a proxy or
                        // origin may select a different value. Never promote a
                        // default-pair observation from one of several headers.
                        // Inspect wire bytes before redaction; retain no value.
                        if (SensitiveTelemetryContracts.IsKnownDefaultBasicAuthorizationValue(line.Slice(colon + 1)))
                            defaultBasicObserved = true;
                    }

                    // Classify sensitive header values in the byte span, before redaction.
                    // Require a complete header block below before promoting the flags.
                    if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("Private-Token", StringComparison.OrdinalIgnoreCase) ||
                        name.Equals("X-Gitlab-Token", StringComparison.OrdinalIgnoreCase))
                    {
                        var value = line.Slice(colon + 1);
                        githubTokenObserved |= HasProviderTokenPrefix(value, "ghp_", 20) || HasProviderTokenPrefix(value, "gho_", 20) || HasProviderTokenPrefix(value, "ghu_", 20) || HasProviderTokenPrefix(value, "ghs_", 20) || HasProviderTokenPrefix(value, "ghr_", 20) || HasProviderTokenPrefix(value, "github_pat_", 30);
                        gitlabTokenObserved |= HasProviderTokenPrefix(value, "glpat-", 20);
                    }
                    if (name.Equals("X-Vault-Token", StringComparison.OrdinalIgnoreCase))
                    {
                        vaultHeaderCount++;
                        vaultTokenObserved |= HasProviderTokenPrefix(line.Slice(colon + 1), "hvs.", 20)
                            || HasProviderTokenPrefix(line.Slice(colon + 1), "hvb.", 20)
                            || HasProviderTokenPrefix(line.Slice(colon + 1), "s.", 20);
                    }
                    if (name.Equals("X-Amz-Target", StringComparison.OrdinalIgnoreCase))
                    {
                        awsTargetCount++;
                        awsListSecretsObserved |= TrimHeaderValue(line, colon + 1).Equals("secretsmanager.ListSecrets", StringComparison.Ordinal);
                    }
                    if (name.Equals("Authorization", StringComparison.OrdinalIgnoreCase))
                    {
                        var value = line.Slice(colon + 1);
                        terraformTokenObserved |= HasProviderTokenPrefix(value, "atlasv1.", 20);
                        npmTokenObserved |= HasProviderTokenPrefix(value, "npm_", 24);
                        pypiUploadAuthorizationObserved |= HasAuthorizationScheme(value, "Basic ") || HasAuthorizationScheme(value, "Bearer ");
                    }
                    if (name.Equals("Circle-Token", StringComparison.OrdinalIgnoreCase))
                    {
                        circleCiHeaderCount++;
                        circleCiTokenObserved |= IsExactCircleToken(line.Slice(colon + 1));
                    }
                    // Avoid allocating a managed string for bearer secrets at all.
                    // Preserve only the header name and a redaction marker in telemetry.
                    bool sensitive = name.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("Cookie", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("X-Api-Key", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("X-aws-ec2-metadata-token", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("X-Identity-Header", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("X-Auth-Token", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("X-Amz-Security-Token", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("Private-Token", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("X-Gitlab-Token", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("Circle-Token", StringComparison.OrdinalIgnoreCase) ||
                                     name.Equals("X-Vault-Token", StringComparison.OrdinalIgnoreCase);
                    var val = sensitive ? "[REDACTED]" : TrimHeaderValue(line, colon + 1);
                    sbJoin.Append(name).Append(": ").Append(val).Append("\r\n");
                    if (name.Equals("Host", StringComparison.OrdinalIgnoreCase)) host = val;
                    else if (name.Equals("User-Agent", StringComparison.OrdinalIgnoreCase)) ua = val;
                }
            }
            return new HttpInfo
            {
                Method = method,
                Path = azurePatUrlObserved ? RedactAzurePatQuery(path!) : path,
                Host = host,
                UserAgent = ua,
                HttpVersion = httpVersion,
                JoinedHeaderLines = sbJoin.ToString(),
                ObservedDefaultBasicCredential = headerSectionComplete && defaultBasicObserved && authorizationHeaderCount == 1,
                ObservedGitHubTokenPattern = headerSectionComplete && authorizationHeaderCount <= 1 && githubTokenObserved,
                ObservedGitLabTokenPattern = headerSectionComplete && authorizationHeaderCount <= 1 && gitlabTokenObserved,
                ObservedAzureDevOpsPatUrlPattern = headerSectionComplete && method != null && azurePatUrlObserved,
                ObservedCircleCiTokenPattern = headerSectionComplete && method != null && circleCiHeaderCount == 1 && circleCiTokenObserved,
                ObservedVaultTokenPattern = headerSectionComplete && method != null && vaultHeaderCount == 1 && vaultTokenObserved,
                ObservedTerraformTokenPattern = headerSectionComplete && method != null && authorizationHeaderCount == 1 && terraformTokenObserved,
                ObservedNpmTokenPattern = headerSectionComplete && method != null && authorizationHeaderCount == 1 && npmTokenObserved,
                ObservedPyPiUploadAuthorization = headerSectionComplete && method != null && authorizationHeaderCount == 1 && pypiUploadAuthorizationObserved,
                ObservedAwsListSecretsRequest = headerSectionComplete && method != null && awsTargetCount == 1 && awsListSecretsObserved,
                HeaderNames = headerNames
            };
        }

        // Token-shaped query values are classified before the retained URI is
        // sanitized. The observed bit is not proof of a valid credential.
        private static readonly Regex AzurePatQuery = new(
            @"([?&](?:pat|token|access_token|personal_access_token)=)[A-Za-z0-9_-]{52,}(?=[&#]|$)",
            RegexOptions.Compiled | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase,
            TimeSpan.FromMilliseconds(100));

        private static bool HasAzurePatQuery(string? path)
            => path != null && path.Length <= 4096 && AzurePatQuery.IsMatch(path);

        private static string RedactAzurePatQuery(string path)
            => AzurePatQuery.Replace(path, "$1[REDACTED]");

        private static bool IsExactCircleToken(ReadOnlySpan<byte> raw)
        {
            var value = TrimStartSpacesTabs(raw);
            if (value.Length != 40) return false;
            foreach (var b in value)
                if (!((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')))
                    return false;
            return true;
        }

        private static bool HasAuthorizationScheme(ReadOnlySpan<byte> raw, string scheme)
        {
            var value = TrimStartSpacesTabs(raw);
            if (value.Length <= scheme.Length || !value.StartsWith(Encoding.ASCII.GetBytes(scheme))) return false;
            var remainder = value.Slice(scheme.Length);
            if (remainder.Length < 8 || remainder.Length > 2048) return false;
            foreach (var b in remainder)
                if (!((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '+' || b == '/' || b == '=' || b == '_' || b == '-' || b == '.')) return false;
            return true;
        }

        private static bool HasProviderTokenPrefix(ReadOnlySpan<byte> value, string prefix, int minSuffix)
        {
            // ASCII-only, allocation-free inspection. Do not persist the matched span.
            for (int i = 0; i + prefix.Length + minSuffix <= value.Length; i++)
            {
                bool matches = true;
                for (int j = 0; j < prefix.Length; j++)
                    if (value[i + j] != (byte)prefix[j]) { matches = false; break; }
                if (!matches) continue;
                int end = i + prefix.Length;
                while (end < value.Length && ((value[end] >= 'a' && value[end] <= 'z') ||
                       (value[end] >= 'A' && value[end] <= 'Z') ||
                       (value[end] >= '0' && value[end] <= '9') ||
                       value[end] == '_' || (prefix == "glpat-" && value[end] == '-'))) end++;
                if (end - i - prefix.Length >= minSuffix) return true;
            }
            return false;
        }

        private static bool TryParseRequestLine(ReadOnlySpan<byte> line, out string? method, out string? path, out string? ver)
        {
            method = null; path = null; ver = null;
            int sp = line.IndexOf((byte)' ');
            if (sp <= 0 || sp > 16) return false;
            method = ToAscii(line.Slice(0, sp));

            var rest = line.Slice(sp + 1);
            int sp2 = rest.IndexOf((byte)' ');
            if (sp2 <= 0) return false;
            path = ToAscii(rest.Slice(0, sp2));
            ver = ToAscii(rest.Slice(sp2 + 1));
            return true;
        }

        private static string TrimHeaderValue(ReadOnlySpan<byte> line, int colonIndexPlusOne)
        {
            var v = line.Slice(colonIndexPlusOne);
            v = TrimStartSpacesTabs(v);
            return ToAscii(v);
        }

        private static ReadOnlySpan<byte> TrimStartSpacesTabs(ReadOnlySpan<byte> s)
        {
            int i = 0;
            while (i < s.Length)
            {
                byte b = s[i];
                if (b == (byte)' ' || b == (byte)'\t') { i++; continue; }
                break;
            }
            return s.Slice(i);
        }

        private static bool StartsWith(ReadOnlySpan<byte> span, string ascii) => span.StartsWith(Encoding.ASCII.GetBytes(ascii));
        private static string ToAscii(ReadOnlySpan<byte> span) => Encoding.ASCII.GetString(span);
    }

    internal static class TlsLight
    {
        internal sealed class TlsInfo
        {
            public string? ServerName { get; set; }
            public string? Alpn { get; set; }
            public string? VersionLabel { get; set; }
            public string? Ja3 { get; set; }
        }

        public static bool LooksLikeTlsRecord(ReadOnlySpan<byte> data) => data.Length >= 5 && data[0] == 0x16;

        public static bool TryParseClientHello(ReadOnlySpan<byte> tlsRecord, out TlsInfo info)
        {
            info = new TlsInfo();

            if (tlsRecord.Length < 5 || tlsRecord[0] != 0x16) return false;
            ushort recLen = BinaryPrimitives.ReadUInt16BigEndian(tlsRecord.Slice(3, 2));
            if (5 + recLen > tlsRecord.Length) return false;
            var body = tlsRecord.Slice(5, recLen);
            if (body.Length < 4 || body[0] != 0x01) return false;

            return TryParseClientHelloBody(body, out info);
        }

        private static bool TryParseClientHelloBody(ReadOnlySpan<byte> body, out TlsInfo info)
        {
            info = new TlsInfo();
            int hsLen = (body[1] << 16) | (body[2] << 8) | body[3];
            if (hsLen + 4 > body.Length) return false;

            var span = body.Slice(4);
            if (span.Length < 2 + 32) return false;

            ushort legacyVersion = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(0, 2));
            info.VersionLabel = legacyVersion switch
            {
                0x0301 => "TLS1.0",
                0x0302 => "TLS1.1",
                0x0303 => "TLS1.2",
                0x0304 => "TLS1.3*",
                _ => $"0x{legacyVersion:X4}"
            };

            int idx = 2 + 32;
            if (idx >= span.Length) return false;

            byte sidLen = span[idx++];
            if (sidLen > span.Length - idx) return false;
            idx += sidLen;

            if (idx + 2 > span.Length) return false;
            ushort csLen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2)); idx += 2;
            if (csLen == 0 || (csLen & 1) != 0 || csLen > span.Length - idx) return false;
            var ciphers = span.Slice(idx, csLen); idx += csLen;

            if (idx >= span.Length) return false;
            byte compLen = span[idx++];
            if (compLen > span.Length - idx) return false;
            idx += compLen;

            var extTypes = new List<ushort>();
            var groups = new List<ushort>();
            var ecpf = new List<byte>();
            string? sni = null, alpn = null;

            if (idx + 2 <= span.Length)
            {
                ushort extTotal = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2)); idx += 2;
                if (idx + extTotal <= span.Length)
                {
                    int exEnd = idx + extTotal;
                    while (idx + 4 <= exEnd)
                    {
                        ushort etype = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx, 2));
                        ushort elen = BinaryPrimitives.ReadUInt16BigEndian(span.Slice(idx + 2, 2));
                        idx += 4;
                        if (idx + elen > exEnd) break;
                        var extData = span.Slice(idx, elen);
                        idx += elen;

                        extTypes.Add(etype);

                        if (etype == 0x0000) // server_name
                        {
                            if (extData.Length >= 5)
                            {
                                int p = 2;
                                if (p + 3 <= extData.Length && extData[p] == 0x00)
                                {
                                    ushort nameLen = BinaryPrimitives.ReadUInt16BigEndian(extData.Slice(p + 1, 2));
                                    p += 3;
                                    if (p + nameLen <= extData.Length)
                                        sni = Encoding.ASCII.GetString(extData.Slice(p, nameLen));
                                }
                            }
                        }
                        else if (etype == 0x0010) // ALPN
                        {
                            if (extData.Length >= 3)
                            {
                                int p = 2;
                                if (p < extData.Length)
                                {
                                    byte l = extData[p++];
                                    if (p + l <= extData.Length)
                                        alpn = Encoding.ASCII.GetString(extData.Slice(p, l));
                                }
                            }
                        }
                        else if (etype == 0x000A) // supported_groups
                        {
                            if (extData.Length >= 2)
                            {
                                int p = 2;
                                while (p + 2 <= extData.Length)
                                {
                                    groups.Add(BinaryPrimitives.ReadUInt16BigEndian(extData.Slice(p, 2)));
                                    p += 2;
                                }
                            }
                        }
                        else if (etype == 0x000B) // ec_point_formats
                        {
                            if (extData.Length >= 1)
                            {
                                int p = 1;
                                while (p < extData.Length) ecpf.Add(extData[p++]);
                            }
                        }
                    }
                }
            }

            info.ServerName = sni;
            info.Alpn = alpn;

            // Legacy JA3 for continuity
            var ver = legacyVersion.ToString();
            var csIds = JoinU16(ciphers);
            var exIds = string.Join("-", extTypes.FindAll(id => !IsGrease(id)));
            var grpIds = string.Join("-", groups.FindAll(id => !IsGrease(id)));
            var ecpfIds = string.Join("-", ecpf);
            string ja3Str = $"{ver},{csIds},{exIds},{grpIds},{ecpfIds}";
            info.Ja3 = MD5Hex(ja3Str);
            return true;
        }

        private static string JoinU16(ReadOnlySpan<byte> buf)
        {
            if (buf.Length % 2 != 0) return "";
            var list = new List<ushort>(buf.Length / 2);
            for (int i = 0; i < buf.Length; i += 2)
            {
                ushort id = BinaryPrimitives.ReadUInt16BigEndian(buf.Slice(i, 2));
                if (!IsGrease(id)) list.Add(id);
            }
            return string.Join("-", list);
        }

        private static bool IsGrease(ushort value) =>
            (value & 0x0F0F) == 0x0A0A && (value >> 8) == (value & 0xFF);

        private static string MD5Hex(string s)
        {
            using var md5 = System.Security.Cryptography.MD5.Create();
            var bytes = Encoding.ASCII.GetBytes(s);
            var hash = md5.ComputeHash(bytes);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (var b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    internal static class QuicLight
    {
        internal sealed class QuicInfo { public string? VersionLabel { get; set; } }

        public static bool TryDetectQuic(ReadOnlySpan<byte> data, out QuicInfo info)
        {
            info = new QuicInfo();
            if (data.Length < 5) return false;
            // Only recognize QUIC long headers with the required fixed bit.
            if ((data[0] & 0xC0) != 0xC0) return false;
            uint version = BinaryPrimitives.ReadUInt32BigEndian(data.Slice(1, 4));
            if (version == 0) return false;
            info.VersionLabel = $"0x{version:X8}";
            return true;
        }
    }

    internal static class DnsLight
    {
        internal sealed class DnsInfo
        {
            public bool IsResponse { get; init; }
            public string? QName { get; init; }
            public string? QType { get; init; }
            public string? Rcode { get; init; }
        }

        public static bool TryParse(ReadOnlySpan<byte> data, bool isTcp, out DnsInfo info)
        {
            info = new DnsInfo();
            if (isTcp)
            {
                if (data.Length < 2) return false;
                ushort len = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(0, 2));
                if (len < 12 || len + 2 > data.Length) return false;
                data = data.Slice(2, len);
            }
            int idx = 0;
            if (data.Length < 12) return false;

            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(idx + 2, 2));
            bool isResp = (flags & 0x8000) != 0;
            int rcode = flags & 0x000F;
            ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(idx + 4, 2));
            int p = idx + 12;

            string? qname = null;
            ushort qtype = 0;

            if (qdCount > 0)
            {
                if (!TryReadQName(data, p, out qname, out p)) return false;
                if (p + 4 > data.Length) return false;
                qtype = BinaryPrimitives.ReadUInt16BigEndian(data.Slice(p, 2));
            }

            info = new DnsInfo
            {
                IsResponse = isResp,
                QName = qname,
                QType = QTypeToString(qtype),
                Rcode = RcodeToString(rcode)
            };
            return qname != null;
        }

        private static bool TryReadQName(ReadOnlySpan<byte> data, int start, out string? name, out int next)
        {
            name = null;
            next = start;
            var sb = new StringBuilder(128);
            int cursor = start;
            int consumedAt = -1;
            int hops = 0;
            int labelCount = 0;

            while (cursor < data.Length && ++hops <= 128)
            {
                byte len = data[cursor++];
                if (len == 0)
                {
                    next = consumedAt >= 0 ? consumedAt : cursor;
                    name = sb.ToString();
                    return true;
                }

                if ((len & 0xC0) == 0xC0)
                {
                    if (cursor >= data.Length || ++labelCount > 127) return false;
                    int ptr = ((len & 0x3F) << 8) | data[cursor++];
                    if (consumedAt < 0) consumedAt = cursor;
                    // RFC 1035 compression pointers point backward. This also rejects loops.
                    if (ptr >= cursor - 2 || ptr >= data.Length) return false;
                    cursor = ptr;
                    continue;
                }

                if ((len & 0xC0) != 0 || len > 63 ||
                    ++labelCount > 127 || cursor + len > data.Length) return false;
                if (sb.Length > 0) sb.Append('.');
                if (sb.Length + len > 253) return false;
                sb.Append(Encoding.ASCII.GetString(data.Slice(cursor, len)));
                cursor += len;
            }

            return false;
        }

        private static string QTypeToString(ushort qtype) => qtype switch
        {
            1 => "A",
            2 => "NS",
            5 => "CNAME",
            6 => "SOA",
            12 => "PTR",
            15 => "MX",
            16 => "TXT",
            28 => "AAAA",
            33 => "SRV",
            255 => "ANY",
            _ => qtype == 0 ? "?" : qtype.ToString()
        };

        private static string RcodeToString(int r) => r switch
        {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => r.ToString()
        };
    }
}
