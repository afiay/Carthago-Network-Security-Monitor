// SPDX-License-Identifier: MIT
using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;
using Carthago.Contracts;

namespace Carthago.Cli;

public static class ServiceCommands
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    public static async Task<int> RunAsync(string action, IServiceControl control, TextWriter output, TextWriter error,
        bool json, CancellationToken token, Func<ServiceHealthSnapshot>? read = null,
        Func<int, DateTimeOffset?>? processStart = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        read ??= () => ServiceHealthStore.Read(ServiceHealthStore.DefaultPath);
        processStart ??= GetProcessStart;
        delay ??= Task.Delay;
        try
        {
            token.ThrowIfCancellationRequested();
            var status = control.Status();
            if (action is "start" or "stop")
            {
                ScmState target = action == "start" ? ScmState.Running : ScmState.Stopped;
                ScmState pending = action == "start" ? ScmState.StartPending : ScmState.StopPending;
                ScmState initial = action == "start" ? ScmState.Stopped : ScmState.Running;
                if (status.State == initial)
                {
                    token.ThrowIfCancellationRequested();
                    if (action == "start") control.Start(); else control.Stop();
                }
                else if (status.State != target && status.State != pending)
                    throw new InvalidOperationException("Service is in an incompatible state.");
                // Fixed bounded poll count; native SCM calls themselves are synchronous.
                for (int i = 0; status.State != target && i < 60; i++)
                {
                    await delay(TimeSpan.FromMilliseconds(500), token).ConfigureAwait(false);
                    token.ThrowIfCancellationRequested();
                    status = control.Status();
                    if (status.State != pending && status.State != target)
                        throw new InvalidOperationException("Service did not reach requested state.");
                }
                if (status.State != target) throw new TimeoutException("SCM transition not confirmed.");
            }
            string health = "not_queried";
            ServiceHealthSnapshot? snapshot = null;
            if (action is "health" or "doctor")
            {
                health = "service_not_running";
                if (status.State == ScmState.Running && status.ProcessId > 0)
                {
                    try
                    {
                        var candidate = read();
                        health = ServiceHealthStore.Assess(candidate, status.ProcessId, processStart(status.ProcessId), DateTimeOffset.UtcNow);
                        // Recheck SCM after reading; do not attach a sample across service replacement.
                        var after = control.Status();
                        if (after.State != ScmState.Running || after.ProcessId != status.ProcessId ||
                            (health == "fresh_sample" && processStart(after.ProcessId) != candidate.ProcessStartedUtc))
                            health = "service_changed";
                        status = after;
                        if (health == "fresh_sample") snapshot = candidate;
                    }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or InvalidDataException or ArgumentException)
                    { health = "snapshot_unavailable"; }
                }
            }
            token.ThrowIfCancellationRequested();
            var assessment = action is "health" or "doctor" ? PipelineHealth.Assess(snapshot?.Counters,
                snapshot?.SampledUtc, DateTimeOffset.UtcNow, status.State == ScmState.Running) : null;
            var payload = new { schemaVersion = 1, service = WindowsServiceControl.ServiceName,
                scmState = status.State.ToString().ToLowerInvariant(), status.ProcessId, status.Win32ExitCode,
                operation = action, health, snapshot, assessment, sourceHealth = "not_assessed", detectionValidation = "not_assessed" };
            await output.WriteLineAsync(json ? JsonSerializer.Serialize(payload, Json) :
                $"CarthagoMonitor: {status.State}; PID {status.ProcessId}; health: {health}." +
                (snapshot is null ? "" : $" Captured: {snapshot.Counters.Captured}; parsed: {snapshot.Counters.Parsed}; detections: {snapshot.Counters.Detections}.") + (assessment is null ? "" : $" Pipeline: {assessment.State}."));
            // Doctor/health fail if no current sample, while status reports SCM state as-is.
            return (action is "health" or "doctor") && (health != "fresh_sample" || assessment?.State == "failed" ||
                (snapshot?.SchemaVersion == 2 && assessment?.State == "unknown")) ? 3 : 0;
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested) { return 130; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            string code = ex is Win32Exception w ? w.NativeErrorCode switch
            { 5 => "access_denied", 1060 => "service_not_installed", _ => "scm_error" } :
                ex is TimeoutException ? "transition_timeout" : "service_operation_failed";
            await error.WriteLineAsync(json ? JsonSerializer.Serialize(new { schemaVersion = 1, error = code,
                message = "Service operation not confirmed." }, Json) : $"Service operation not confirmed: {code}.");
            return 3;
        }
    }

    private static DateTimeOffset? GetProcessStart(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return new DateTimeOffset(process.StartTime.ToUniversalTime());
        }
        catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException)
        { return null; }
    }
}
