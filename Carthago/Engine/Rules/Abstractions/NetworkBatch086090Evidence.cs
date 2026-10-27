// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    // R086–R090 inspect only wire-attributed HTTP request fields. Packet Info,
    // DNS, TLS metadata, free-text logs and raw bodies cannot manufacture matches.
    internal static class NetworkBatch086090Evidence
    {
        private const RegexOptions PatternOptions =
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;

        internal static bool TryTarget(RuleEvaluationContext c, out string target)
        {
            target = string.Empty;
            if (!NetworkBatch081085Evidence.HttpRequest(c)
                || string.IsNullOrEmpty(c.Record.HttpUri)) return false;
            // Refuse ambiguous decoding and truncation, rather than matching a prefix.
            var raw = c.Record.HttpUri;
            if (raw.Length > 4096 || raw.IndexOf('\0') >= 0) return false;
            target = raw;
            try
            {
                for (var pass = 0; pass < 2; pass++)
                {
                    var decoded = Uri.UnescapeDataString(target.Replace("+", " "));
                    if (decoded.Length > 4096) return false;
                    if (decoded == target) break;
                    target = decoded;
                }
            }
            catch (UriFormatException) { return false; }
            return target.Length <= 4096;
        }

        private static bool Pattern(string value, string regex)
        {
            try
            {
                return Regex.IsMatch(value, regex, PatternOptions,
                    TimeSpan.FromMilliseconds(50));
            }
            catch (RegexMatchTimeoutException) { return false; }
        }

        internal static bool Traversal(string s)
        {
            // Traversal requires BOTH an upward path component and a sensitive target.
            // A benign literal "../" used in prose is not sufficient.
            return Pattern(s, @"(?:^|[/?=&\\])\.\.[/\\]")
                && Pattern(s, @"(?:etc[/\\]passwd|etc[/\\]shadow|windows[/\\]win\.ini|web-inf[/\\]web\.xml)");
        }

        internal static bool ScriptUpload(RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!new[] { "POST", "PUT", "PATCH" }.Contains(r.HttpMethod,
                StringComparer.OrdinalIgnoreCase)) return false;
            // Explicit parsed parser classification is independent evidence.
            if (!string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.ApplicationService, "SCRIPT_UPLOAD_OBSERVED",
                    StringComparison.OrdinalIgnoreCase)) return false;
            if (string.IsNullOrEmpty(r.HttpRequestHeaders)) return false;
            var headers = r.HttpRequestHeaders;
            if (!Pattern(headers, @"(?:^|\r\n)content-type:\s*multipart/form-data\s*;\s*boundary=[a-z0-9'()+_,./:=?-]{1,70}(?:\r\n|;)"))
                return false;
            return true;
        }

        internal static bool Deserialization(RuleEvaluationContext c, string s)
        {
            if (!string.Equals(c.Record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(c.Record.ApplicationService, "DESERIALIZATION_PAYLOAD_OBSERVED",
                    StringComparison.OrdinalIgnoreCase)) return false;
            // Require a parser classification AND recognized language-specific token.
            return Pattern(s, @"(?:rO0AB[A-Za-z0-9+/=]{8,}|ObjectDataProvider|BinaryFormatter|LosFormatter|ysoserial)");
        }

        internal static bool CommandInjection(string s)
        {
            // Operator boundary and an executable shell command must co-occur.
            return Pattern(s, @"(?:[;&|]{1,2}|\$\()\s*(?:/bin/(?:sh|bash)|cmd\.exe|whoami\b|id\b|curl\b|wget\b|powershell(?:\.exe)?\b)");
        }

        internal static bool ReverseShell(string s)
        {
            // Do not alert on the words "reverse shell" alone, or a generic bash command.
            return Pattern(s, @"(?:bash\s+-i.{0,100}/dev/tcp/[a-z0-9.:-]+/\d{1,5}|nc(?:at)?\s+-e\s+(?:/bin/(?:sh|bash)|cmd\.exe)\s+[a-z0-9.:-]+\s+\d{1,5}|socat\s+tcp:[a-z0-9.:-]+:\d{1,5},exec:)");
        }

        internal static RuleEvaluationResult Match(RuleDescriptor d,
            RuleEvaluationContext c, string description)
            => NetworkBatch081085Evidence.Match(d, c, description);
    }
}
