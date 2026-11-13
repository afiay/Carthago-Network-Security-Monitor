// SPDX-License-Identifier: MIT
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Reflection;
using Carthago.Contracts;
using Carthago.Services;
using Carthago.Services.Sensors;

namespace Carthago.ActiveQualification;

// Dedicated synthetic qualification executable, not a production monitor command.
// Default and child modes are synthetic. Explicit live mode is separately gated.
internal static class Program
{
    private static readonly Guid AdapterId = Guid.Parse("02702701-1234-4321-9999-000000000001");
    private static readonly LocalLanInterface Adapter = new("qualification", IPAddress.Parse("192.168.50.10"), IPAddress.Parse("255.255.255.0"));
    private static readonly IPAddress Target = IPAddress.Parse("192.168.50.11");
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);
    private static string DirectoryFor(Guid id) => Path.Combine(Path.GetTempPath(), "carthago-process-qualification-" + id.ToString("N"));
    private static string Reservation(Guid id) => @"Global\Carthago.Test.ActiveScheduler." + id.ToString("N");
    private static SnmpCredentialVault Vault(Guid id) => new(Path.Combine(DirectoryFor(id), "vault.db"));
    private static ActiveSensorProfileStore Store(Guid id) => new(Path.Combine(DirectoryFor(id), "profiles.db"), vault: Vault(id));
    private static SnmpCredentialScope Scope() => SnmpCredentialScope.Create(AdapterId, Adapter, Target);
    private static ActiveSensorProfile Profile(bool snmp) => ActiveSensorProfile.Create(AdapterId, Adapter, Target,
        snmp ? ActiveSensorKind.Snmp : ActiveSensorKind.Dns, snmp ? "" : "lab.example", snmp ? 161 : 53,
        TimeSpan.FromMinutes(5), true);

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args is ["--child", var idText, var mode] && Guid.TryParseExact(idText, "N", out var id) &&
                id != Guid.Empty && mode is "hold" or "contend" or "revoke" or "rotate")
                return await ChildAsync(id, mode);
            if (args is ["--live-contract"]) return LiveSensorLab.VerifyContract();
            if (args.Length > 0 && args[0] == "live") return await LiveSensorLab.RunAsync(args);
            if (args.Length != 0) return 2;
            if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows required.");
            await ScenarioAsync("graceful");
            await ScenarioAsync("crash");
            await ScenarioAsync("revoke");
            await ScenarioAsync("rotate");
            Console.WriteLine("PASS AS-Q07G3 4/4 separate-process scenarios");
            return 0;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // No credential values, paths or raw database exception messages.
            Console.Error.WriteLine($"FAIL AS-Q07G3: {ex.GetType().Name}");
            return 1;
        }
    }

    private static async Task ScenarioAsync(string scenario)
    {
        var id = Guid.NewGuid();
        string dir = DirectoryFor(id);
        Directory.CreateDirectory(dir);
        try
        {
            bool snmp = scenario == "rotate";
            var profile = Profile(snmp);
            var store = Store(id);
            Require(store.Save(profile), "fixture save");
            Guid? generation = snmp ? Vault(id).Save(Scope(), new SnmpCredential("lab-user", "authphrase", "privphrase")) : null;
            if (snmp) Require(generation.HasValue, "fixture credential save");
            var grant = store.Grant(profile, TimeSpan.FromHours(1), generation);
            Require(grant is not null, "fixture grant");
            using var owner = Start(id, scenario is "revoke" or "rotate" ? scenario : "hold");
            try
            {
                await ExpectAsync(owner, "READY");
                if (scenario is "graceful" or "crash")
                {
                    using var contender = Start(id, "contend");
                    try { await ExpectAsync(contender, "CONTENDED"); await ExitAsync(contender, 0); }
                    finally { await StopAsync(contender); }
                    if (scenario == "crash")
                    {
                        owner.Kill(entireProcessTree: true);
                        await owner.WaitForExitAsync().WaitAsync(Timeout);
                        Require(owner.ExitCode != 0, "abrupt termination did not fail");
                    }
                    else
                    {
                        await CommandAsync(owner, "stop");
                        await ExpectAsync(owner, "STOPPED");
                        await ExitAsync(owner, 0);
                    }
                    // Reacquire in a new process, not by reusing the parent's handle.
                    using var successor = Start(id, "hold");
                    try
                    {
                        await ExpectAsync(successor, "READY");
                        await CommandAsync(successor, "stop");
                        await ExpectAsync(successor, "STOPPED");
                        await ExitAsync(successor, 0);
                    }
                    finally { await StopAsync(successor); }
                }
                else
                {
                    // Owner has finished loading the grant and entered its injected probe;
                    // no database handle is held across this process synchronization point.
                    if (snmp)
                    {
                        var replacement = Vault(id).Save(Scope(), new SnmpCredential("lab-user", "newauthphrase", "newprivphrase"));
                        Require(replacement.HasValue && replacement != generation, "rotation");
                    }
                    else Require(store.Revoke(grant!.Id), "revocation");
                    Require(!store.IsAuthorized(profile, grant!.GrantId), "old grant still valid");
                    await CommandAsync(owner, "finish");
                    await ExpectAsync(owner, "BLOCKED_NO_WRITE");
                    await ExitAsync(owner, 0);
                    var replacementGrant = store.Grant(profile, TimeSpan.FromHours(1), snmp ? Vault(id).GetGeneration(Scope()) : null);
                    Require(replacementGrant is not null && replacementGrant.GrantId != grant.GrantId &&
                        !store.IsAuthorized(profile, grant.GrantId), "replacement resurrected old grant");
                }
            }
            finally { await StopAsync(owner); }
            Console.WriteLine($"PASS {scenario}");
        }
        finally { Directory.Delete(dir, recursive: true); }
    }

    private static Process Start(Guid id, string mode)
    {
        var host = Environment.ProcessPath ?? throw new InvalidOperationException("No process host.");
        var psi = new ProcessStartInfo(host)
        {
            UseShellExecute = false, RedirectStandardInput = true, RedirectStandardOutput = true,
            RedirectStandardError = true, CreateNoWindow = true
        };
        if (string.Equals(Path.GetFileNameWithoutExtension(host), "dotnet", StringComparison.OrdinalIgnoreCase))
            psi.ArgumentList.Add(Assembly.GetExecutingAssembly().Location);
        psi.ArgumentList.Add("--child"); psi.ArgumentList.Add(id.ToString("N")); psi.ArgumentList.Add(mode);
        return Process.Start(psi) ?? throw new InvalidOperationException("Child start failed.");
    }

    private static async Task ExpectAsync(Process child, string expected)
    {
        string? line = await child.StandardOutput.ReadLineAsync().WaitAsync(Timeout);
        Require(line == expected, "Unexpected child protocol marker: " + expected);
    }
    private static async Task CommandAsync(Process child, string command)
    {
        await child.StandardInput.WriteLineAsync(command);
        await child.StandardInput.FlushAsync();
    }
    private static async Task ExitAsync(Process child, int code)
    {
        await child.WaitForExitAsync().WaitAsync(Timeout);
        Require(child.ExitCode == code, "Unexpected child exit.");
    }
    private static async Task StopAsync(Process child)
    {
        if (!child.HasExited) child.Kill(entireProcessTree: true);
        await child.WaitForExitAsync().WaitAsync(Timeout);
    }

    private static async Task<int> ChildAsync(Guid id, string mode)
    {
        // Child cannot choose a file path or a production reservation name.
        Require(Directory.Exists(DirectoryFor(id)), "Fixture directory missing.");
        bool snmp = mode == "rotate";
        var store = Store(id);
        var p = Profile(snmp);
        var grant = store.ReadValidGrant(p);
        Require(grant is not null, "Fixture grant unavailable.");
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(60));
        int probes = 0, writes = 0;
        async Task<ActiveSensorRun> Probe(CancellationToken token)
        {
            probes++;
            if (mode == "contend") throw new InvalidOperationException("Contender ran probe.");
            Console.WriteLine("READY");
            Console.Out.Flush();
            string? command = await Console.In.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(45), token);
            if (mode == "hold")
            {
                Require(command == "stop", "Unexpected stop command.");
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
            }
            Require(command == "finish", "Unexpected finish command.");
            return new ActiveSensorRun("Observed", true, new ActiveEvidenceRow());
        }
        var manager = new ActiveSensorManager(resolve: _ => Adapter,
            probe: (_, _, token) => Probe(token), save: _ => { writes++; return true; },
            acquireReservation: () => WindowsActiveSchedulerReservation.AcquireNamed(Reservation(id)),
            snmpProbe: (_, _, secret, token) =>
            {
                Require(secret.User == "lab-user" && secret.Authentication == "authphrase" &&
                    secret.Privacy == "privphrase", "Unexpected credential.");
                return Probe(token);
            });
        manager.AddAuthorized(p, store, grant!.GrantId);
        try
        {
            await manager.RunAsync(cancellation.Token, stopWhenAllBlocked: true);
        }
        catch (InvalidOperationException ex) when (mode == "contend" && ex.Message.Contains("Another Carthago active scheduler", StringComparison.Ordinal))
        {
            Require(probes == 0 && writes == 0 && !manager.HasReservation, "Contender side effect.");
            Console.WriteLine("CONTENDED"); return 0;
        }
        catch (OperationCanceledException) when (mode == "hold" && cancellation.IsCancellationRequested)
        {
            Require(probes == 1 && writes == 0 && !manager.HasReservation &&
                manager.Snapshot().Single().LastOutcome == "Cancelled", "Shutdown not clean.");
            Console.WriteLine("STOPPED"); return 0;
        }
        Require(mode is "revoke" or "rotate", "Unexpected scheduler exit.");
        Require(probes == 1 && writes == 0 && !manager.HasReservation &&
            manager.Snapshot().Single().ScopeBlocked, "Revoked probe wrote evidence or did not block.");
        Console.WriteLine("BLOCKED_NO_WRITE");
        return 0;
    }
}
