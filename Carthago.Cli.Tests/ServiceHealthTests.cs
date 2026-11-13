// SPDX-License-Identifier: MIT
using System.ComponentModel;
using System.Text.Json;
using Carthago.Contracts;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class ServiceHealthTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 12, 0, 0, TimeSpan.Zero);
    private static ServiceHealthSnapshot Sample(DateTimeOffset now)
        => new(1, Guid.NewGuid(), 123, now.AddMinutes(-10), now, new(42, 40, 2, 3));

    [Fact]
    public void CurrentSampleRequiresMatchingProcessBirthAndPid()
    {
        var s = Sample(Now);
        Assert.Equal("fresh_sample", ServiceHealthStore.Assess(s, 123, s.ProcessStartedUtc, Now));
        Assert.Equal("process_mismatch", ServiceHealthStore.Assess(s, 124, s.ProcessStartedUtc, Now));
        Assert.Equal("process_mismatch", ServiceHealthStore.Assess(s, 123, s.ProcessStartedUtc.AddSeconds(1), Now));
        Assert.Equal("process_identity_unavailable", ServiceHealthStore.Assess(s, 123, null, Now));
    }

    [Fact]
    public void SampleAgeAndFutureBoundary()
    {
        var s = Sample(Now);
        Assert.Equal("fresh_sample", ServiceHealthStore.Assess(s, 123, s.ProcessStartedUtc, Now.AddSeconds(120)));
        Assert.Equal("stale", ServiceHealthStore.Assess(s, 123, s.ProcessStartedUtc, Now.AddSeconds(121)));
        Assert.Equal("future_sample", ServiceHealthStore.Assess(s, 123, s.ProcessStartedUtc, Now.AddSeconds(-1)));
    }

    [Fact]
    public void AtomicWriteReadAndReplace()
    {
        WithPath(path =>
        {
            var s = Sample(Now);
            ServiceHealthStore.Write(path, s);
            Assert.Equal(s, ServiceHealthStore.Read(path));
            var next = s with { SampledUtc = Now.AddSeconds(5), Counters = new(50, 48, 2, 4) };
            ServiceHealthStore.Write(path, next);
            Assert.Equal(next, ServiceHealthStore.Read(path));
            Assert.Single(Directory.GetFiles(Path.GetDirectoryName(path)!));
        });
    }

    [Fact]
    public void RejectMissingDuplicateUnknownAndOversize()
    {
        WithPath(path =>
        {
            string json = JsonSerializer.Serialize(Sample(Now), new JsonSerializerOptions(JsonSerializerDefaults.Web));
            File.WriteAllText(path, json.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"));
            Assert.Throws<InvalidDataException>(() => ServiceHealthStore.Read(path));
            File.WriteAllText(path, json.Replace("\"captured\":42,", ""));
            Assert.Throws<InvalidDataException>(() => ServiceHealthStore.Read(path));
            File.WriteAllText(path, json.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"extra\":1"));
            Assert.Throws<InvalidDataException>(() => ServiceHealthStore.Read(path));
            File.WriteAllBytes(path, new byte[ServiceHealthStore.MaxBytes + 1]);
            Assert.Throws<InvalidDataException>(() => ServiceHealthStore.Read(path));
        });
    }

    [Fact]
    public async Task StartWaitsForScmConfirmation()
    {
        var scm = new Fake(new(ScmState.Stopped, 0, 0), new(ScmState.StartPending, 123, 0), new(ScmState.Running, 123, 0));
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(0, await ServiceCommands.RunAsync("start", scm, output, error, true, default, delay: (_, _) => Task.CompletedTask));
        Assert.Equal(1, scm.Starts);
        Assert.Contains("\"scmState\":\"running\"", output.ToString());
    }

    [Fact]
    public async Task StopWaitsForScmConfirmation()
    {
        var scm = new Fake(new(ScmState.Running, 123, 0), new(ScmState.StopPending, 123, 0), new(ScmState.Stopped, 0, 0));
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(0, await ServiceCommands.RunAsync("stop", scm, output, error, true, default, delay: (_, _) => Task.CompletedTask));
        Assert.Equal(1, scm.Stops);
        Assert.Contains("\"scmState\":\"stopped\"", output.ToString());
    }

    [Fact]
    public async Task TransitionTimeoutDoesNotClaimSuccess()
    {
        var scm = new Fake(new(ScmState.StartPending, 123, 0));
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(3, await ServiceCommands.RunAsync("start", scm, output, error, true, default, delay: (_, _) => Task.CompletedTask));
        Assert.Empty(output.ToString());
        Assert.Contains("transition_timeout", error.ToString());
    }

    [Theory]
    [InlineData(5, "access_denied")]
    [InlineData(1060, "service_not_installed")]
    public async Task ScmErrorsAreExplicit(int nativeCode, string expected)
    {
        var scm = new Fake(new(ScmState.Stopped, 0, 0)) { Error = nativeCode };
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(3, await ServiceCommands.RunAsync("status", scm, output, error, true, default));
        Assert.Empty(output.ToString());
        Assert.Contains(expected, error.ToString());
    }

    [Fact]
    public async Task HealthDoesNotReadStoppedServiceSnapshot()
    {
        var scm = new Fake(new(ScmState.Stopped, 0, 0));
        using var output = new StringWriter();
        using var error = new StringWriter();
        bool called = false;
        Assert.Equal(3, await ServiceCommands.RunAsync("health", scm, output, error, true, default,
            read: () => { called = true; return Sample(Now); }));
        Assert.False(called);
        Assert.Contains("service_not_running", output.ToString());
        Assert.Contains("\"snapshot\":null", output.ToString());
    }

    [Fact]
    public async Task HealthRejectsServiceReplacementDuringRead()
    {
        var s = Sample(DateTimeOffset.UtcNow);
        var scm = new Fake(new(ScmState.Running, 123, 0), new(ScmState.Running, 456, 0));
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(3, await ServiceCommands.RunAsync("health", scm, output, error, true, default,
            read: () => s, processStart: _ => s.ProcessStartedUtc));
        Assert.Contains("service_changed", output.ToString());
        Assert.Contains("\"snapshot\":null", output.ToString());
    }

    [Fact]
    public async Task DoctorReportsFreshSampleWithoutClaimingDetectorAccuracy()
    {
        var s = Sample(DateTimeOffset.UtcNow);
        var scm = new Fake(new(ScmState.Running, 123, 0));
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(0, await ServiceCommands.RunAsync("doctor", scm, output, error, true, default,
            read: () => s, processStart: _ => s.ProcessStartedUtc));
        Assert.Contains("fresh_sample", output.ToString());
        Assert.Contains("\"detectionValidation\":\"not_assessed\"", output.ToString());
    }

    [Fact]
    public async Task CancellationAfterRequestDoesNotClaimRollback()
    {
        using var cancel = new CancellationTokenSource();
        var scm = new Fake(new(ScmState.Stopped, 0, 0));
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.Equal(130, await ServiceCommands.RunAsync("start", scm, output, error, true, cancel.Token,
            delay: (_, _) => { cancel.Cancel(); return Task.CompletedTask; }));
        Assert.Equal(1, scm.Starts);
        Assert.Empty(output.ToString());
    }

    private static void WithPath(Action<string> action)
    {
        string dir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dir);
        try { action(Path.Combine(dir, "monitor.json")); }
        finally { Directory.Delete(dir, true); }
    }

    private sealed class Fake : IServiceControl
    {
        private readonly Queue<ScmStatus> _states;
        private ScmStatus _last;
        public int Starts, Stops;
        public int? Error;
        public Fake(params ScmStatus[] states) { _states = new(states); _last = states[0]; }
        public ScmStatus Status()
        {
            if (Error is int error) throw new Win32Exception(error);
            if (_states.Count > 0) _last = _states.Dequeue();
            return _last;
        }
        public void Start() => Starts++;
        public void Stop() => Stops++;
    }
}
