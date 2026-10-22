// SPDX-License-Identifier: MIT
// File: Models/CiscoSyslogEvent.cs

using System;
using System.Globalization;

namespace Carthago.Models
{
    /// <summary>
    /// Normalized representation of a Cisco syslog message with
    /// additional inferred metadata (device name, Cisco code, category, etc.).
    /// </summary>
    public class CiscoSyslogEvent
    {
        /// <summary>Arrival time on this host (UTC).</summary>
        public DateTime Timestamp { get; set; }

        /// <summary>Remote IP address of the sender.</summary>
        public string Host { get; set; } = string.Empty;

        /// <summary>Numeric facility extracted from the PRI field (0–23) as string.</summary>
        public string Facility { get; set; } = string.Empty;

        /// <summary>Numeric severity extracted from the PRI field (0–7) as string.</summary>
        public string Severity { get; set; } = string.Empty;

        /// <summary>Message payload after PRI, as received.</summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>Raw datagram contents (best-effort decoded).</summary>
        public string Raw { get; set; } = string.Empty;

        // --- Lazy-parsed Cisco metadata ---

        private bool _parsed;
        private string _deviceName = string.Empty;
        private string _ciscoCode = string.Empty;
        private string _ciscoMnemonic = string.Empty;
        private string _shortMessage = string.Empty;
        private string _category = string.Empty;

        /// <summary>Hostname from the syslog payload (e.g. "R1").</summary>
        public string DeviceName
        {
            get { EnsureParsed(); return _deviceName; }
        }

        /// <summary>Cisco syslog code, e.g. SYS-5-CONFIG_I, LINEPROTO-5-UPDOWN.</summary>
        public string CiscoCode
        {
            get { EnsureParsed(); return _ciscoCode; }
        }

        /// <summary>High-level Cisco mnemonic (e.g. SYS, LINEPROTO, CRYPTO).</summary>
        public string CiscoMnemonic
        {
            get { EnsureParsed(); return _ciscoMnemonic; }
        }

        /// <summary>Message with prefixes stripped (sequence/timestamp), just the human text.</summary>
        public string ShortMessage
        {
            get
            {
                EnsureParsed();
                return string.IsNullOrEmpty(_shortMessage) ? Message : _shortMessage;
            }
        }

        /// <summary>Inferred high-level category (Config change, Interface state, Security / ACL, ...).</summary>
        public string Category
        {
            get
            {
                EnsureParsed();
                return string.IsNullOrEmpty(_category) ? "General" : _category;
            }
        }

        /// <summary>Prefer Cisco hostname if available, otherwise the remote IP.</summary>
        public string DeviceOrHost => string.IsNullOrEmpty(DeviceName) ? Host : DeviceName;

        /// <summary>Parsed severity code (0–7) or null if Severity is not numeric.</summary>
        public int? SeverityCode
        {
            get =>
                int.TryParse(Severity, NumberStyles.Integer, CultureInfo.InvariantCulture, out var code)
                    ? code
                    : (int?)null;
        }

        /// <summary>Human-friendly severity name derived from SeverityCode.</summary>
        public string SeverityName
        {
            get
            {
                if (!SeverityCode.HasValue)
                    return Severity;

                return SeverityCode.Value switch
                {
                    0 => "Emergency",
                    1 => "Alert",
                    2 => "Critical",
                    3 => "Error",
                    4 => "Warning",
                    5 => "Notice",
                    6 => "Informational",
                    7 => "Debug",
                    _ => Severity
                };
            }
        }

        /// <summary>Parsed facility code (0–23) or null if Facility is not numeric.</summary>
        public int? FacilityCode
        {
            get =>
                int.TryParse(Facility, NumberStyles.Integer, CultureInfo.InvariantCulture, out var f)
                    ? f
                    : (int?)null;
        }

        /// <summary>Human-friendly facility name for the numeric FacilityCode.</summary>
        public string FacilityName
        {
            get
            {
                if (!FacilityCode.HasValue)
                    return Facility;

                return FacilityCode.Value switch
                {
                    0 => "kernel",
                    1 => "user",
                    2 => "mail",
                    3 => "daemon",
                    4 => "auth",
                    5 => "syslog",
                    6 => "lpr",
                    7 => "news",
                    8 => "uucp",
                    9 => "clock",
                    10 => "authpriv",
                    11 => "ftp",
                    12 => "ntp",
                    13 => "audit",
                    14 => "alert",
                    15 => "clock2",
                    16 => "local0",
                    17 => "local1",
                    18 => "local2",
                    19 => "local3",
                    20 => "local4",
                    21 => "local5",
                    22 => "local6",
                    23 => "local7",
                    _ => Facility
                };
            }
        }

        /// <summary>Short one-line summary combining CiscoCode and ShortMessage.</summary>
        public string Summary =>
            string.IsNullOrEmpty(CiscoCode)
                ? ShortMessage
                : $"{CiscoCode}: {ShortMessage}";

        // --- Internal parse helpers ---

        private void EnsureParsed()
        {
            if (_parsed)
                return;

            _parsed = true;
            ParseCiscoMessage(
                Message,
                out _deviceName,
                out _ciscoCode,
                out _ciscoMnemonic,
                out _shortMessage,
                out _category);
        }

        private static void ParseCiscoMessage(
            string message,
            out string deviceName,
            out string code,
            out string mnemonic,
            out string shortMessage,
            out string category)
        {
            deviceName = string.Empty;
            code = string.Empty;
            mnemonic = string.Empty;
            shortMessage = string.Empty;
            category = string.Empty;

            if (string.IsNullOrWhiteSpace(message))
                return;

            string w = message.Trim();

            // Drop leading numeric prefixes like "36:" or "000032:"
            while (true)
            {
                int colon = w.IndexOf(':');
                if (colon <= 0)
                    break;

                string before = w[..colon];
                if (int.TryParse(before, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
                {
                    w = w[(colon + 1)..].TrimStart();
                }
                else
                {
                    break;
                }
            }

            // Optional hostname prefix "R1:" (no spaces)
            {
                int colon = w.IndexOf(':');
                if (colon > 0)
                {
                    string candidate = w[..colon];
                    if (!candidate.Contains(' ', StringComparison.Ordinal))
                    {
                        deviceName = candidate;
                        w = w[(colon + 1)..].TrimStart();
                    }
                }
            }

            // Another numeric sequence number "000028:" etc
            while (true)
            {
                int colon = w.IndexOf(':');
                if (colon <= 0)
                    break;

                string before = w[..colon];
                if (int.TryParse(before, NumberStyles.Integer, CultureInfo.InvariantCulture, out _))
                {
                    w = w[(colon + 1)..].TrimStart();
                }
                else
                {
                    break;
                }
            }

            // Skip timestamp until '%' if present
            int percent = w.IndexOf('%');
            if (percent >= 0)
                w = w[percent..].TrimStart();

            // Now we expect "%SYS-5-CONFIG_I: actual message"
            int firstColon = w.IndexOf(':');
            if (w.StartsWith('%') && firstColon > 0)
            {
                code = w[1..firstColon].Trim();
                shortMessage = w[(firstColon + 1)..].Trim();

                int dash = code.IndexOf('-');
                if (dash > 0)
                    mnemonic = code[..dash];
            }
            else
            {
                shortMessage = w;
            }

            // Category inference – cheap heuristics, but surprisingly effective.
            string up = (code + " " + shortMessage).ToUpperInvariant();

            if (up.Contains("CONFIG_I", StringComparison.Ordinal) ||
                up.Contains("CONFIG ", StringComparison.Ordinal))
            {
                category = "Config change";
            }
            else if (up.Contains("LINEPROTO", StringComparison.Ordinal) ||
                     up.Contains("UPDOWN", StringComparison.Ordinal) ||
                     up.Contains("LINK-5-CHANGED", StringComparison.Ordinal))
            {
                category = "Interface state";
            }
            else if (up.Contains("SEC-", StringComparison.Ordinal) ||
                     up.Contains("IPACCESSLOGP", StringComparison.Ordinal) ||
                     up.Contains("ACL", StringComparison.Ordinal))
            {
                category = "Security / ACL";
            }
            else if (up.Contains("CRYPTO", StringComparison.Ordinal) ||
                     up.Contains("ISAKMP", StringComparison.Ordinal) ||
                     up.Contains("IPSEC", StringComparison.Ordinal) ||
                     up.Contains("VPN", StringComparison.Ordinal))
            {
                category = "VPN / Crypto";
            }
            else if (up.Contains("SNMP", StringComparison.Ordinal))
            {
                category = "SNMP";
            }
            else if (up.Contains("SYS-5-RESTART", StringComparison.Ordinal) ||
                     up.Contains("RELOAD", StringComparison.Ordinal))
            {
                category = "System restart";
            }
            else
            {
                category = "General";
            }
        }
    }
}
