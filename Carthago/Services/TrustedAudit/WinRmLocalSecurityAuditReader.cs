// SPDX-License-Identifier: MIT
// Read-only LOCAL Windows Security log intake. Not an audit signer.
using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Linq;
using System.Security;

namespace Carthago.Services.TrustedAudit
{
    /// <summary>
    /// Reads only the local Windows Security channel (4624 network logons
    /// and 4688 process creation). The operating system controls access.
    /// This class never changes auditing policy, privileges or event logs.
    /// </summary>
    public sealed class WinRmLocalSecurityAuditReader
    {
        private const string LocalSecurityLog = "Security";
        private const string SecurityProvider = "Microsoft-Windows-Security-Auditing";
        private const string EventQuery =
            "*[System[Provider[@Name='Microsoft-Windows-Security-Auditing'] and (EventID=4624 or EventID=4688)]]";

        /// <summary>
        /// Returns UNSIGNED candidate associations only. Even records read
        /// from local Security are insufficient to attest successful remote
        /// command execution or promote R343. No raw XML or command lines
        /// are returned, persisted or logged by this reader.
        /// </summary>
        public bool TryReadRecent(
            out IReadOnlyList<WinRmAuditCandidate> candidates,
            out string reason, int maxRecords = 512)
        {
            candidates = Array.Empty<WinRmAuditCandidate>();
            reason = "SECURITY_LOG_UNAVAILABLE";
            if (maxRecords is < 1 or > 4096)
            {
                reason = "INVALID_READ_LIMIT";
                return false;
            }
            if (!OperatingSystem.IsWindows())
            {
                reason = "WINDOWS_ONLY_SOURCE";
                return false;
            }

            var events = new List<WinRmSecurityAuditObservation>();
            var ids = new HashSet<long>();
            try
            {
                var query = new EventLogQuery(LocalSecurityLog, PathType.LogName, EventQuery)
                {
                    ReverseDirection = true,
                    TolerateQueryErrors = false
                };
                using var reader = new EventLogReader(query);
                for (var i = 0; i < maxRecords; ++i)
                {
                    using var record = reader.ReadEvent();
                    if (record == null)
                        break;

                    if (record.Id is not (4624 or 4688)
                        || !string.Equals(record.LogName, LocalSecurityLog,
                            StringComparison.Ordinal)
                        || !string.Equals(record.ProviderName, SecurityProvider,
                            StringComparison.Ordinal)
                        || record.RecordId is not > 0
                        || !ids.Add(record.RecordId.Value))
                        continue;

                    // Native EventRecord metadata is checked against XML and
                    // current machine before even producing an untrusted
                    // candidate. Do not accept event-file/replay XML here.
                    if (WinRmSecurityAuditIntake.TryInspectLocalRecord(
                            record.ToXml(), record.LogName, record.ProviderName,
                            record.MachineName, record.Id, record.RecordId,
                            record.TimeCreated, out var observation, out _)
                        && observation != null)
                        events.Add(observation);
                }
            }
            catch (UnauthorizedAccessException)
            {
                reason = "SECURITY_LOG_ACCESS_DENIED";
                return false;
            }
            catch (SecurityException)
            {
                reason = "SECURITY_LOG_ACCESS_DENIED";
                return false;
            }
            catch (EventLogException)
            {
                reason = "SECURITY_LOG_UNAVAILABLE";
                return false;
            }
            catch (PlatformNotSupportedException)
            {
                reason = "WINDOWS_EVENT_LOG_API_UNAVAILABLE";
                return false;
            }

            var logons = events.Where(x =>
                    x.Kind == WinRmSecurityObservationKind.NetworkLogon)
                .GroupBy(x => (x.Machine, x.LogonId))
                .ToDictionary(g => g.Key, g => g.OrderByDescending(x => x.TimeUtc).ToArray());
            var result = new List<WinRmAuditCandidate>();
            var emitted = new HashSet<long>();
            foreach (var process in events
                .Where(x => x.Kind == WinRmSecurityObservationKind.EncodedPowerShellProcessCreation)
                .OrderByDescending(x => x.TimeUtc))
            {
                if (!logons.TryGetValue((process.Machine, process.LogonId),
                        out var candidatesForSession))
                    continue;
                foreach (var logon in candidatesForSession)
                {
                    if (!WinRmSecurityAuditIntake.TryCorrelateCandidate(
                        logon, process, out var candidate, out _) || candidate == null)
                        continue;

                    if (emitted.Add(process.RecordId))
                        result.Add(candidate);
                    break;
                }
                if (result.Count >= 64)
                    break;
            }

            candidates = result;
            reason = "UNATTESTED_LOCAL_AUDIT_CANDIDATES_ONLY";
            return true;
        }
    }
}
