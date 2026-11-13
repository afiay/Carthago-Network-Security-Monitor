// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Contracts;

namespace Carthago.Services.Sensors;

// Session-only authorization. No credentials, arbitrary paths, or persistent auto-start.
internal sealed record ActiveSensorProfile(Guid Id, Guid AdapterId, LocalLanInterface Adapter,
    IPAddress Target, ActiveSensorKind Kind, string HostName, int Port, TimeSpan Interval, bool SaveHistory)
{
    internal static ActiveSensorProfile Create(Guid adapterId, LocalLanInterface adapter, IPAddress target,
        ActiveSensorKind kind, string hostName, int port, TimeSpan interval, bool saveHistory)
    {
        ArgumentNullException.ThrowIfNull(adapter);
        ArgumentNullException.ThrowIfNull(target);
        if (adapterId == Guid.Empty || !LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(target))
            throw new ArgumentException("Select an approved local IPv4 target and adapter.");
        if (interval < TimeSpan.FromMinutes(5) || interval > TimeSpan.FromHours(24))
            throw new ArgumentException("Interval must be between five minutes and 24 hours.");
        if (kind is not (ActiveSensorKind.Tcp or ActiveSensorKind.Dns or ActiveSensorKind.Tls or ActiveSensorKind.Http or ActiveSensorKind.Snmp))
            throw new ArgumentException("This sensor is manual-only.");
        if (kind == ActiveSensorKind.Tcp) { hostName = ""; port = 0; }
        else if (kind == ActiveSensorKind.Snmp) { hostName = ""; port = 161; }
        else
        {
            hostName = DnsIntegritySensor.NormalizeName(hostName);
            if (kind == ActiveSensorKind.Dns) port = 53;
            else if (kind == ActiveSensorKind.Tls && !TlsInspectionSensor.AllowedPorts.Contains(port) ||
                     kind == ActiveSensorKind.Http && !HttpHealthSensor.AllowedPorts.Contains(port))
                throw new ArgumentException("Port is not approved for this sensor.");
        }
        return new(Guid.NewGuid(), adapterId, adapter, target, kind, hostName, port, interval, saveHistory);
    }
}

internal sealed record ActiveSensorRun(string Outcome, bool Responsive, ActiveEvidenceRow? Evidence);
internal sealed record ActiveSensorScheduleState(ActiveSensorProfile Profile, DateTimeOffset NextDueUtc,
    DateTimeOffset? LastRunUtc, string LastOutcome, int ConsecutiveFailures, bool Running,
    bool ScopeBlocked, string HistoryStatus);

internal sealed class ActiveSensorManager
{
    internal const int MaxProfiles = 16;
    private readonly object _gate = new();
    private readonly Dictionary<Guid, ActiveSensorScheduleState> _states = new();
    private readonly Dictionary<Guid, (ActiveSensorProfileStore Store, Guid GrantId)> _grants = new();
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<ActiveSensorProfile, LocalLanInterface?> _resolve;
    private readonly Func<ActiveSensorProfile, LocalLanInterface, CancellationToken, Task<ActiveSensorRun>> _probe;
    private readonly Func<ActiveEvidenceRow, bool> _save;
    private readonly Func<ActiveSensorProfile, LocalLanInterface, SnmpCredential, CancellationToken, Task<ActiveSensorRun>> _snmpProbe;
    private readonly Func<IDisposable> _acquireReservation;
    private readonly bool _allowsTestTick;
    private bool _busy;
    private bool _loopActive;

    internal ActiveSensorManager(Func<DateTimeOffset>? clock = null,
        Func<ActiveSensorProfile, LocalLanInterface?>? resolve = null,
        Func<ActiveSensorProfile, LocalLanInterface, CancellationToken, Task<ActiveSensorRun>>? probe = null,
        Func<ActiveEvidenceRow, bool>? save = null, Func<IDisposable>? acquireReservation = null,
        Func<ActiveSensorProfile, LocalLanInterface, SnmpCredential, CancellationToken, Task<ActiveSensorRun>>? snmpProbe = null)
    {
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _resolve = resolve ?? Resolve;
        _probe = probe ?? ProbeAsync;
        _snmpProbe = snmpProbe ?? ProbeSnmpAsync;
        _save = save ?? (row => new ActiveEvidenceStore().Save(row));
        _acquireReservation = acquireReservation ?? WindowsActiveSchedulerReservation.Acquire;
        _allowsTestTick = probe is not null || snmpProbe is not null;
    }

    internal void Add(ActiveSensorProfile p) => AddCore(p, null, Guid.Empty);

    internal void AddAuthorized(ActiveSensorProfile p, ActiveSensorProfileStore store, Guid grantId)
    {
        ArgumentNullException.ThrowIfNull(store);
        if (!store.IsAuthorized(p, grantId)) throw new InvalidOperationException("Durable authorization unavailable or expired.");
        AddCore(p, store, grantId);
    }

    private void AddCore(ActiveSensorProfile p, ActiveSensorProfileStore? store, Guid grantId)
    {
        if (p.Kind == ActiveSensorKind.Snmp && store is null)
            throw new InvalidOperationException("Scheduled SNMP requires a credential-bound durable grant.");
        // Revalidate even if a caller directly constructs an internal record.
        var valid = ActiveSensorProfile.Create(p.AdapterId, p.Adapter, p.Target, p.Kind, p.HostName,
            p.Port, p.Interval, p.SaveHistory);
        if (p.Id == Guid.Empty || p.HostName != valid.HostName || p.Port != valid.Port)
            throw new ArgumentException("Invalid profile.");
        lock (_gate)
        {
            if (_busy || _loopActive) throw new InvalidOperationException("Stop the scheduler before changing profiles.");
            if (_states.Count >= MaxProfiles) throw new InvalidOperationException("Profile limit reached.");
            if (_states.Values.Any(s => s.Profile.AdapterId == p.AdapterId &&
                s.Profile.Adapter.Address.Equals(p.Adapter.Address) && s.Profile.Target.Equals(p.Target) &&
                s.Profile.Kind == p.Kind && s.Profile.HostName == p.HostName && s.Profile.Port == p.Port))
                throw new InvalidOperationException("This endpoint and sensor are already approved.");
            _states.Add(p.Id, new(p, _clock(), null, "Not run", 0, false, false, "Not requested"));
            if (store is not null) _grants.Add(p.Id, (store, grantId));
        }
    }

    internal bool Remove(Guid id)
    {
        lock (_gate)
        {
            if (_busy || _loopActive) return false;
            _grants.Remove(id);
            return _states.Remove(id);
        }
    }

    private bool Authorized(ActiveSensorProfile p) => !_grants.TryGetValue(p.Id, out var grant) ||
        grant.Store.IsAuthorized(p, grant.GrantId);

    private bool _reserved;
    internal bool HasReservation { get { lock (_gate) return _reserved; } }

    internal IReadOnlyList<ActiveSensorScheduleState> Snapshot()
    {
        lock (_gate) return _states.Values.OrderBy(s => s.NextDueUtc).ThenBy(s => s.Profile.Id).ToArray();
    }

    internal static TimeSpan NextDelay(TimeSpan interval, int failures)
    {
        if (failures <= 0) return interval;
        // Never retry more frequently than the approved interval.
        return TimeSpan.FromTicks(Math.Min(TimeSpan.FromHours(24).Ticks,
            interval.Ticks * (1L << Math.Min(failures, 5))));
    }

    // Deterministic test seam: a standalone tick is permitted only with an
    // injected probe, never alongside the production loop. Production callers
    // must use RunAsync, which holds the machine-wide reservation.
    internal Task<bool> RunDueAsync(CancellationToken token)
    {
        if (!_allowsTestTick) throw new InvalidOperationException("Use the reserved scheduler loop.");
        return RunDueCoreAsync(token, fromLoop: false);
    }

    private async Task<bool> RunDueCoreAsync(CancellationToken token, bool fromLoop)
    {
        token.ThrowIfCancellationRequested();
        ActiveSensorScheduleState state;
        lock (_gate)
        {
            if (_busy || _loopActive != fromLoop) return false;
            var now = _clock();
            var due = _states.Values.Where(s => !s.ScopeBlocked && s.NextDueUtc <= now)
                .OrderBy(s => s.NextDueUtc).ThenBy(s => s.Profile.Id).FirstOrDefault();
            if (due is null) return false;
            state = due;
            _busy = true;
            _states[state.Profile.Id] = state with { Running = true };
        }
        var p = state.Profile;
        string outcome = "Probe failed", history = "Not requested";
        int failures = state.ConsecutiveFailures;
        bool blocked = false;
        try
        {
            token.ThrowIfCancellationRequested();
            var adapter = _resolve(p);
            token.ThrowIfCancellationRequested();
            if (adapter is null || !adapter.Address.Equals(p.Adapter.Address) ||
                !adapter.Mask.Equals(p.Adapter.Mask) ||
                !LocalLanDiscovery.PlanProbeTargets(new[] { adapter }).Contains(p.Target))
            {
                blocked = true;
                outcome = "Scope changed — remove and reapprove";
                return true;
            }
            if (!Authorized(p))
            {
                blocked = true;
                outcome = "Authorization expired, revoked or unavailable — remove and reapprove";
                return true;
            }
            token.ThrowIfCancellationRequested();
            ActiveSensorRun result;
            if (p.Kind == ActiveSensorKind.Snmp)
            {
                var binding = _grants[p.Id];
                var secret = binding.Store.LoadAuthorizedSnmp(p, binding.GrantId);
                if (secret is null)
                {
                    blocked = true;
                    outcome = "SNMP credential or grant unavailable — remove and reapprove";
                    return true;
                }
                token.ThrowIfCancellationRequested();
                if (!Authorized(p))
                {
                    blocked = true;
                    outcome = "SNMP authorization ended before transport";
                    return true;
                }
                result = await _snmpProbe(p, adapter, secret, token).ConfigureAwait(false);
            }
            else result = await _probe(p, adapter, token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            if (!Authorized(p))
            {
                blocked = true;
                outcome = "Authorization ended during probe — evidence not saved";
                history = p.SaveHistory ? "Not saved" : "Not requested";
                return true;
            }
            outcome = result.Outcome;
            failures = result.Responsive ? 0 : Math.Min(failures + 1, 30);
            if (p.SaveHistory)
            {
                history = "Not saved";
                if (result.Evidence is not null)
                {
                    token.ThrowIfCancellationRequested();
                    if (!Authorized(p))
                    {
                        blocked = true;
                        outcome = "Authorization ended before persistence — evidence not saved";
                        return true;
                    }
                    try { history = _save(result.Evidence) ? "Saved" : "Storage failed"; }
                    catch (Exception ex) when (ex is not OutOfMemoryException) { history = "Storage failed"; }
                }
            }
            return true;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            outcome = "Cancelled";
            throw;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            failures = Math.Min(failures + 1, 30);
            return true;
        }
        finally
        {
            lock (_gate)
            {
                var now = _clock();
                _states[p.Id] = state with { Running = false, LastRunUtc = now, LastOutcome = outcome,
                    ConsecutiveFailures = failures, ScopeBlocked = blocked, HistoryStatus = history,
                    NextDueUtc = blocked ? DateTimeOffset.MaxValue : now + NextDelay(p.Interval, failures) };
                _busy = false;
            }
        }
    }

    internal async Task RunAsync(CancellationToken token, bool stopWhenAllBlocked = false)
    {
        token.ThrowIfCancellationRequested();
        lock (_gate)
        {
            if (_loopActive || _busy) throw new InvalidOperationException("This scheduler is already running.");
            if (_states.Count == 0) throw new InvalidOperationException("No session profiles approved.");
            _loopActive = true;
        }
        try
        {
            // Do not start a single probe until native ownership is established.
            // Dispose only after the current probe and any synchronous save finish.
            using var reservation = _acquireReservation() ??
                throw new InvalidOperationException("Active scheduler reservation unavailable.");
            lock (_gate) _reserved = true;
            token.ThrowIfCancellationRequested();
            while (true)
            {
                await RunDueCoreAsync(token, fromLoop: true).ConfigureAwait(false);
                if (stopWhenAllBlocked)
                {
                    lock (_gate)
                        if (_states.Values.All(s => s.ScopeBlocked)) return;
                }
                await Task.Delay(TimeSpan.FromSeconds(1), token).ConfigureAwait(false);
            }
        }
        finally
        {
            lock (_gate) { _reserved = false; _loopActive = false; }
        }
    }

    private static LocalLanInterface? Resolve(ActiveSensorProfile p) =>
        LocalLanDiscovery.GetLocalInterfaces(p.AdapterId).FirstOrDefault(a =>
            a.Address.Equals(p.Adapter.Address) && a.Mask.Equals(p.Adapter.Mask));

    private static async Task<ActiveSensorRun> ProbeSnmpAsync(ActiveSensorProfile p, LocalLanInterface adapter,
        SnmpCredential secret, CancellationToken token)
    {
        var snmp = await SnmpInfrastructureSensor.CheckAsync(adapter, p.Target, secret.User,
            secret.Authentication, secret.Privacy, token).ConfigureAwait(false);
        return new(snmp.Status.ToString(), snmp.Status is SnmpInfrastructureStatus.Observed or SnmpInfrastructureStatus.Partial,
            ActiveEvidenceProjection.From(p.AdapterId, snmp));
    }

    private static async Task<ActiveSensorRun> ProbeAsync(ActiveSensorProfile p, LocalLanInterface adapter,
        CancellationToken token)
    {
        switch (p.Kind)
        {
            case ActiveSensorKind.Tcp:
                var tcp = await TcpExposureSensor.ScanAsync(adapter, p.Target, token).ConfigureAwait(false);
                bool response = tcp.Any(v => v.Status is TcpExposureStatus.Open or TcpExposureStatus.Refused);
                return new(response ? "TCP response observed" : "TCP inconclusive", response,
                    ActiveEvidenceProjection.From(p.AdapterId, tcp));
            case ActiveSensorKind.Dns:
                var dns = await DnsIntegritySensor.CheckAsync(adapter, p.Target, p.HostName, Array.Empty<IPAddress>(), token).ConfigureAwait(false);
                return new(dns.Status.ToString(), dns.Status is DnsIntegrityStatus.AnswersObserved or
                    DnsIntegrityStatus.NoAddress or DnsIntegrityStatus.NameError or DnsIntegrityStatus.DnsError,
                    ActiveEvidenceProjection.From(p.AdapterId, dns));
            case ActiveSensorKind.Tls:
                var tls = await TlsInspectionSensor.CheckAsync(adapter, p.Target, p.Port, p.HostName, token: token).ConfigureAwait(false);
                return new(tls.Status.ToString(), tls.Status is TlsInspectionStatus.Authenticated or TlsInspectionStatus.CertificateRejected,
                    ActiveEvidenceProjection.From(p.AdapterId, tls));
            case ActiveSensorKind.Http:
                var http = await HttpHealthSensor.CheckAsync(adapter, p.Target, p.Port, p.HostName, token).ConfigureAwait(false);
                return new(http.Status.ToString(), http.Status == HttpHealthStatus.ResponseObserved,
                    ActiveEvidenceProjection.From(p.AdapterId, http));
            default: throw new InvalidOperationException("Manual-only sensor.");
        }
    }
}
