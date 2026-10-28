// SPDX-License-Identifier: MIT
// Windows Security event 4624/4688 prefilter. NEVER an attestation or alert.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;

namespace Carthago.Services.TrustedAudit
{
    public enum WinRmSecurityObservationKind
    {
        NetworkLogon = 4624,
        EncodedPowerShellProcessCreation = 4688
    }

    /// <summary>
    /// Privacy-minimized, UNSIGNED security-log observation.
    /// Caller-supplied XML is always classified as synthetic/untrusted.
    /// Even OS-read observations are NOT authenticated remote execution proof.
    /// </summary>
    public sealed class WinRmSecurityAuditObservation
    {
        internal WinRmSecurityAuditObservation(
            WinRmSecurityObservationKind kind, string machine, long recordId,
            DateTimeOffset timeUtc, ulong logonId, string? remoteIp,
            uint processId, uint parentProcessId, bool fromLocalSecurityLog)
        {
            Kind = kind;
            Machine = machine;
            RecordId = recordId;
            TimeUtc = timeUtc;
            LogonId = logonId;
            RemoteIp = remoteIp;
            ProcessId = processId;
            ParentProcessId = parentProcessId;
            FromLocalSecurityLog = fromLocalSecurityLog;
        }

        public WinRmSecurityObservationKind Kind { get; }
        public string Machine { get; }
        public long RecordId { get; }
        public DateTimeOffset TimeUtc { get; }
        public ulong LogonId { get; }
        public string? RemoteIp { get; }
        public uint ProcessId { get; }
        public uint ParentProcessId { get; }
        // A local Security event read is not a digitally signed remote outcome.
        public bool FromLocalSecurityLog { get; }
    }

    public sealed class WinRmAuditCandidate
    {
        internal WinRmAuditCandidate(
            WinRmSecurityAuditObservation logon, WinRmSecurityAuditObservation process)
        {
            Machine = process.Machine;
            LogonId = process.LogonId;
            RemoteIp = logon.RemoteIp!;
            LogonRecordId = logon.RecordId;
            ProcessRecordId = process.RecordId;
            ProcessId = process.ProcessId;
            ParentProcessId = process.ParentProcessId;
            ProcessTimeUtc = process.TimeUtc;
            FromLocalSecurityLog = logon.FromLocalSecurityLog && process.FromLocalSecurityLog;
        }

        public string Machine { get; }
        public ulong LogonId { get; }
        public string RemoteIp { get; }
        public long LogonRecordId { get; }
        public long ProcessRecordId { get; }
        public uint ProcessId { get; }
        public uint ParentProcessId { get; }
        public DateTimeOffset ProcessTimeUtc { get; }
        public bool FromLocalSecurityLog { get; }
        // Deliberately no: VerifiedAuditReceipt, signature, raw command, or alert status.
    }

    public static class WinRmSecurityAuditIntake
    {
        private const int MaxXmlChars = 32768;
        private const string SecurityProvider = "Microsoft-Windows-Security-Auditing";
        private static readonly XNamespace EventNs =
            "http://schemas.microsoft.com/win/2004/08/events/event";
        private static readonly Regex EncodedFlag = new(
            @"(?:^|\s)-(?:EncodedCommand|enc)\s+[""']?(?<value>[A-Za-z0-9+/=]{8,8192})(?:[""']|\s|$)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
            TimeSpan.FromMilliseconds(100));
        private static readonly UnicodeEncoding StrictUtf16 = new(false, true, true);

        /// <summary>
        /// Synthetic/XML-only input is UNTRUSTED even when every field looks
        /// like Security 4688 or 4624. Use for parser tests and diagnostics,
        /// never to sign a claim or promote R343.
        /// </summary>
        public static bool TryInspectUntrustedXml(string? xml,
            out WinRmSecurityAuditObservation? observation, out string reason)
            => TryInspect(xml, null, null, null, null, null, null,
                false, out observation, out reason);

        /// <summary>
        /// Only the read-only native local Security reader may call this entry.
        /// Native EventRecord properties must agree with the event XML.
        /// </summary>
        internal static bool TryInspectLocalRecord(
            string? xml, string nativeLog, string nativeProvider,
            string nativeMachine, int nativeId, long? nativeRecordId,
            DateTime? nativeTime,
            out WinRmSecurityAuditObservation? observation, out string reason)
            => TryInspect(xml, nativeLog, nativeProvider, nativeMachine,
                nativeId, nativeRecordId, nativeTime, true,
                out observation, out reason);

        // This overload prevents a caller from setting a "local" flag through
        // the public XML-only inspector.
        private static bool TryInspect(string? xml, string? nativeLog,
            string? nativeProvider, string? nativeMachine, int? nativeId,
            long? nativeRecordId, DateTime? nativeTime, bool fromLocal,
            out WinRmSecurityAuditObservation? observation, out string reason)
        {
            observation = null;
            reason = "INVALID_SECURITY_EVENT";
            if (string.IsNullOrWhiteSpace(xml) || xml.Length > MaxXmlChars)
                return false;

            XDocument doc;
            try
            {
                using var input = new StringReader(xml);
                using var reader = XmlReader.Create(input, new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = MaxXmlChars,
                    MaxCharactersFromEntities = 0
                });
                doc = XDocument.Load(reader, LoadOptions.None);
            }
            catch (Exception ex) when (ex is XmlException or ArgumentException)
            {
                return false;
            }

            var root = doc.Root;
            if (root == null || root.Name != EventNs + "Event")
                return false;
            var system = root.Element(EventNs + "System");
            var eventData = root.Element(EventNs + "EventData");
            if (system == null || eventData == null)
                return false;

            var provider = (string?)system.Element(EventNs + "Provider")?.Attribute("Name");
            var channel = (string?)system.Element(EventNs + "Channel");
            var machine = (string?)system.Element(EventNs + "Computer");
            var eventIdText = (string?)system.Element(EventNs + "EventID");
            var recordText = (string?)system.Element(EventNs + "EventRecordID");
            var systemTime = (string?)system.Element(EventNs + "TimeCreated")?.Attribute("SystemTime");
            if (!string.Equals(provider, SecurityProvider, StringComparison.Ordinal)
                || !string.Equals(channel, "Security", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(machine) || machine.Length > 255
                || !int.TryParse(eventIdText, NumberStyles.None, CultureInfo.InvariantCulture, out var id)
                || id is not (4624 or 4688)
                || !long.TryParse(recordText, NumberStyles.None, CultureInfo.InvariantCulture, out var recordId)
                || recordId <= 0
                || !DateTimeOffset.TryParse(systemTime, CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var time)
                || time.Offset != TimeSpan.Zero)
                return false;

            if (fromLocal
                && (!string.Equals(nativeLog, channel, StringComparison.Ordinal)
                    || !string.Equals(nativeProvider, provider, StringComparison.Ordinal)
                    || !string.Equals(nativeMachine, machine, StringComparison.OrdinalIgnoreCase)
                    || !IsLocalMachine(machine)
                    || nativeId != id || nativeRecordId != recordId
                    || nativeTime == null
                    || Math.Abs((nativeTime.Value.ToUniversalTime() - time.UtcDateTime).TotalSeconds) > 2))
            {
                reason = "NATIVE_RECORD_METADATA_MISMATCH";
                return false;
            }

            var fields = new Dictionary<string, string>(StringComparer.Ordinal);
            var dataNodes = eventData.Elements(EventNs + "Data").ToArray();
            if (dataNodes.Length is < 4 or > 50)
                return false;
            foreach (var data in dataNodes)
            {
                var name = (string?)data.Attribute("Name");
                var value = data.Value;
                if (string.IsNullOrWhiteSpace(name) || name.Length > 80
                    || value.Length > 8192 || !fields.TryAdd(name, value))
                    return false;
            }

            if (id == 4624)
            {
                if (!fields.TryGetValue("LogonType", out var logonType)
                    || logonType != "3"
                    || !TryHex(fields, "TargetLogonId", out var logonId)
                    || !fields.TryGetValue("IpAddress", out var remote)
                    || !IPAddress.TryParse(remote, out var ip)
                    || IPAddress.IsLoopback(ip)
                    || (ip.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(ip.MapToIPv4()))
                    || ip.Equals(IPAddress.Any)
                    || ip.Equals(IPAddress.IPv6Any))
                {
                    reason = "NO_NETWORK_LOGON_ATTRIBUTION";
                    return false;
                }

                observation = new WinRmSecurityAuditObservation(
                    WinRmSecurityObservationKind.NetworkLogon, machine, recordId,
                    time, logonId, ip.ToString(), 0, 0, fromLocal);
            }
            else
            {
                if (!fields.TryGetValue("NewProcessName", out var process)
                    || !fields.TryGetValue("ParentProcessName", out var parent)
                    || !fields.TryGetValue("CommandLine", out var commandLine)
                    || !ExactWindowsExecutable(process, "powershell.exe")
                       && !ExactWindowsExecutable(process, "pwsh.exe")
                    || !ExactWindowsExecutable(parent, "wsmprovhost.exe")
                    || !TryHex(fields, "NewProcessId", out var childId)
                    || childId > uint.MaxValue
                    || !TryHex(fields, "ProcessId", out var parentId)
                    || parentId > uint.MaxValue
                    || childId == parentId
                    || !HasValidEncodedArgument(commandLine))
                {
                    reason = "NO_ENCODED_PROCESS_CREATION_ATTRIBUTION";
                    return false;
                }

                // In version 2 a different, nonzero target session can be the
                // newly created process token. Otherwise use creator session.
                var hasTarget = TryHex(fields, "TargetLogonId", out var targetId);
                if (!hasTarget && !TryHex(fields, "SubjectLogonId", out targetId))
                {
                    reason = "MISSING_PROCESS_LOGON_SESSION";
                    return false;
                }

                observation = new WinRmSecurityAuditObservation(
                    WinRmSecurityObservationKind.EncodedPowerShellProcessCreation,
                    machine, recordId, time, targetId, null,
                    (uint)childId, (uint)parentId, fromLocal);
            }

            reason = "UNATTESTED_AUDIT_OBSERVATION";
            return true;
        }

        public static bool TryCorrelateCandidate(
            WinRmSecurityAuditObservation? logon,
            WinRmSecurityAuditObservation? process,
            out WinRmAuditCandidate? candidate, out string reason)
        {
            candidate = null;
            reason = "UNRELATED_SECURITY_EVENTS";
            if (logon == null || process == null
                || logon.Kind != WinRmSecurityObservationKind.NetworkLogon
                || process.Kind != WinRmSecurityObservationKind.EncodedPowerShellProcessCreation
                || !string.Equals(logon.Machine, process.Machine, StringComparison.OrdinalIgnoreCase)
                || logon.FromLocalSecurityLog != process.FromLocalSecurityLog
                || logon.LogonId != process.LogonId
                || logon.RecordId >= process.RecordId
                || logon.TimeUtc > process.TimeUtc
                || process.TimeUtc - logon.TimeUtc > TimeSpan.FromMinutes(10))
                return false;

            candidate = new WinRmAuditCandidate(logon, process);
            reason = "UNATTESTED_CANDIDATE_ONLY";
            return true;
        }

        private static bool TryHex(Dictionary<string, string> values, string key, out ulong parsed)
        {
            parsed = 0;
            return values.TryGetValue(key, out var hex)
                && hex.Length is >= 3 and <= 18
                && hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                && ulong.TryParse(hex.AsSpan(2), NumberStyles.AllowHexSpecifier,
                    CultureInfo.InvariantCulture, out parsed) && parsed != 0;
        }

        private static bool ExactWindowsExecutable(string? value, string name)
        {
            if (value is not { Length: >= 5 and <= 520 }
                || value.Length < 4 || !char.IsAsciiLetter(value[0])
                || value[1] != ':' || value[2] != '\\'
                || value.Contains("..", StringComparison.Ordinal)
                || value.Contains('/', StringComparison.Ordinal)
                || value.Contains('"', StringComparison.Ordinal))
                return false;
            var slash = value.LastIndexOf('\\');
            return slash >= 3
                && string.Equals(value[(slash + 1)..], name, StringComparison.OrdinalIgnoreCase);
        }

        private static bool HasValidEncodedArgument(string? commandLine)
        {
            if (string.IsNullOrWhiteSpace(commandLine) || commandLine.Length > 8192)
                return false;
            try
            {
                var match = EncodedFlag.Match(commandLine);
                if (!match.Success)
                    return false;
                var argument = match.Groups["value"].Value;
                var bytes = Convert.FromBase64String(argument);
                if (bytes.Length is < 4 or > 4096 || (bytes.Length & 1) != 0)
                    return false;
                var decoded = StrictUtf16.GetString(bytes);
                // Never return or log the decoded payload.
                return decoded.Length > 0 && !decoded.Contains('\0');
            }
            catch (Exception ex) when (ex is FormatException
                or DecoderFallbackException or RegexMatchTimeoutException)
            {
                return false;
            }
        }

        private static bool IsLocalMachine(string name)
        {
            var computer = Environment.MachineName;
            return string.Equals(name, computer, StringComparison.OrdinalIgnoreCase)
                || name.StartsWith(computer + ".", StringComparison.OrdinalIgnoreCase);
        }
    }
}
