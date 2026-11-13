// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;
using Carthago.Contracts;

namespace Carthago.Services.Sensors;

public static class ActiveServiceProvisioning
{
    private static bool Id(string s) => s.Length == 64 && s.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    private static IPAddress Address(string value) =>
        IPAddress.TryParse(value, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork &&
        ip.ToString() == value && LocalLanDiscovery.IsLocalHostAddress(ip) ? ip :
            throw new ArgumentException("Canonical local IPv4 required.");

    internal static ActiveSensorProfile ParseProfile(string[] args, Func<Guid, IReadOnlyList<LocalLanInterface>> resolve,
        Func<ActiveSensorProfile, bool> gateway)
    {
        if (args is not ["--adapter", var adapter, "--source", var source, "--target", var target,
            "--sensor", var sensor, "--host", var host, "--port", var port, "--interval", var interval, "--history", var history] ||
            !Guid.TryParseExact(adapter, "D", out var id) || id == Guid.Empty ||
            !Enum.TryParse<ActiveSensorKind>(sensor, out var kind) || kind.ToString() != sensor ||
            !int.TryParse(port, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int p) ||
            !int.TryParse(interval, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out int minutes) ||
            history is not ("true" or "false")) throw new ArgumentException("Invalid profile arguments.");
        var src = Address(source); var dst = Address(target);
        var matches = resolve(id).Where(a => a.Address.Equals(src) &&
            LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(dst)).ToArray();
        if (matches.Length != 1) throw new ArgumentException("Live scope unavailable or ambiguous.");
        var profile = ActiveSensorProfile.Create(id, matches[0], dst, kind, host, p, TimeSpan.FromMinutes(minutes), history == "true");
        if (profile.HostName != host || profile.Port != p) throw new ArgumentException("Use canonical host and port.");
        if (kind == ActiveSensorKind.Gateway && !gateway(profile)) throw new ArgumentException("Target is not configured gateway.");
        return profile;
    }

    private static string ReadSecret(string prompt, int max, CancellationToken token)
    {
        Console.Error.Write(prompt);
        var chars = new char[max]; int count = 0;
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                if (!Console.KeyAvailable) { Thread.Sleep(50); continue; }
                var key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Escape) throw new OperationCanceledException();
                if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); return new string(chars, 0, count); }
                if (key.Key == ConsoleKey.Backspace) { if (count > 0) chars[--count] = '\0'; continue; }
                if (key.KeyChar < 32 || key.KeyChar > 126) continue;
                if (count == max) throw new ArgumentException("Credential too long.");
                chars[count++] = key.KeyChar;
            }
        }
        finally { Array.Clear(chars); }
    }

    private static bool Confirm(string description)
    {
        Console.Error.WriteLine(description);
        Console.Error.Write("Type AUTHORIZE to proceed: ");
        return Console.ReadLine() == "AUTHORIZE";
    }

    internal static byte[] BuildConfiguration(string account, IReadOnlyList<ActiveServiceSelection> profiles)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 1, accountSid = account,
            profiles = profiles.Select(p => new { profileId = p.ProfileId, grantId = p.GrantId.ToString("D") }) },
            new JsonSerializerOptions { WriteIndented = true });
        _ = ActiveServiceConfiguration.Parse(bytes);
        return bytes;
    }

    internal static void WriteConfiguration(string root, byte[] bytes)
    {
        _ = ActiveServiceConfiguration.Parse(bytes);
        string path = Path.Combine(root, ActiveServiceStorage.ConfigName);
        string temp = Path.Combine(root, "config-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(bytes); stream.Flush(true); }
            File.Move(temp, path, overwrite: true);
        }
        finally { if (File.Exists(temp)) File.Delete(temp); }
    }

    public static int Execute(string[] args)
    {
        if (args.Length < 4 || args[1] != "--account-sid" || args[0] is not ("provision" or "configure" or "revoke"))
            return 2;
        if (!OperatingSystem.IsWindows() || !Environment.UserInteractive || Console.IsInputRedirected)
        { Console.Error.WriteLine("Interactive Windows service-account console required."); return 3; }
        using var cancel = new CancellationTokenSource();
        ConsoleCancelEventHandler handler = (_, e) => { e.Cancel = true; cancel.Cancel(); };
        Console.CancelKeyPress += handler;
        try
        {
            var account = ActiveServiceStorage.CurrentAccount(args[2]);
            var remaining = args[3..];
            if (args[0] == "provision")
            {
                ActiveSensorProfile Parse() => ParseProfile(remaining, id => LocalLanDiscovery.GetLocalInterfaces(id),
                    p => GatewayIntegritySensor.IsConfiguredGateway(p.AdapterId, p.Adapter, p.Target));
                var profile = Parse();
                var saved = SavedActiveSensorProfile.From(profile);
                if (!Confirm($"Provision under account {account.Value}: {saved.Label}. Adapter {saved.AdapterId}. " +
                    "Issue a new 24-hour grant; this replaces the previous grant for this profile. No probes or service installation.")) return 3;
                SnmpCredential? credential = null;
                if (profile.Kind == ActiveSensorKind.Snmp)
                    credential = new(ReadSecret("SNMPv3 username: ", 32, cancel.Token),
                        ReadSecret("Authentication passphrase: ", 128, cancel.Token), ReadSecret("Privacy passphrase: ", 128, cancel.Token));
                cancel.Token.ThrowIfCancellationRequested();
                using var lease = WindowsActiveSchedulerReservation.Acquire();
                var current = Parse();
                if (SavedActiveSensorProfile.From(current).ConfigurationDigest() != saved.ConfigurationDigest())
                    throw new InvalidOperationException("Scope changed.");
                string root = ActiveServiceStorage.Root(account, create: true);
                var store = ActiveServiceStorage.Store(root);
                Guid? generation = null;
                if (credential is not null)
                {
                    generation = ActiveServiceStorage.Vault(root).Save(
                        SnmpCredentialScope.Create(profile.AdapterId, profile.Adapter, profile.Target), credential);
                    if (!generation.HasValue) throw new InvalidOperationException("Credential save failed.");
                }
                if (!store.Save(profile)) throw new InvalidOperationException("Profile save failed.");
                var grant = store.Grant(profile, TimeSpan.FromHours(24), generation);
                if (grant is null) throw new InvalidOperationException("Grant save failed.");
                ActiveServiceStorage.CheckTree(root, account);
                Console.WriteLine(JsonSerializer.Serialize(new { profileId = grant.Id, grantId = grant.GrantId,
                    expiresUtc = new DateTime(grant.ExpiresTicks, DateTimeKind.Utc), serviceStarted = false }));
                return 0;
            }
            if (remaining.Length < 2 || remaining.Length % 2 != 0 || remaining.Length > 32) return 2;
            var ids = new List<string>();
            for (int i = 0; i < remaining.Length; i += 2)
            {
                if (remaining[i] != "--profile" || !Id(remaining[i + 1]) || ids.Contains(remaining[i + 1])) return 2;
                ids.Add(remaining[i + 1]);
            }
            if (args[0] == "revoke" && ids.Count != 1) return 2;
            string existing = ActiveServiceStorage.Root(account, create: false);
            var profiles = ActiveServiceStorage.Store(existing);
            if (args[0] == "revoke")
            {
                if (!Confirm($"Revoke service grant for {ids[0]}? Stop the active service first.")) return 3;
                cancel.Token.ThrowIfCancellationRequested();
                using var lease = WindowsActiveSchedulerReservation.Acquire();
                if (!profiles.Revoke(ids[0])) throw new InvalidOperationException("Grant revocation failed.");
                Console.WriteLine("Grant revoked. Existing pinned configuration cannot start with this grant.");
                return 0;
            }
            if (!Confirm($"Replace service configuration for {ids.Count} selected profile(s) under {account.Value}? " +
                "Stop the active service first. No probes or service installation.")) return 3;
            cancel.Token.ThrowIfCancellationRequested();
            using var reservation = WindowsActiveSchedulerReservation.Acquire();
            var rows = profiles.Read();
            if (rows.Error is not null) throw new InvalidOperationException("Profile store unavailable.");
            var selected = new List<ActiveServiceSelection>();
            foreach (string id in ids)
            {
                var row = rows.Rows.SingleOrDefault(r => r.Id == id);
                if (row is null || !row.TryValidate(out var p) || p is null)
                    throw new InvalidOperationException("Selected profile unavailable.");
                var grant = profiles.ReadValidGrant(p);
                if (grant is null) throw new InvalidOperationException("Selected grant unavailable.");
                selected.Add(new(id, grant.GrantId));
            }
            WriteConfiguration(existing, BuildConfiguration(account.Value, selected));
            ActiveServiceStorage.CheckTree(existing, account);
            Console.WriteLine(Path.Combine(existing, ActiveServiceStorage.ConfigName));
            return 0;
        }
        catch (OperationCanceledException) { return 130; }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { Console.Error.WriteLine("Provisioning unavailable or invalid. No service started. Check account, scope, storage and ownership."); return 3; }
        finally { Console.CancelKeyPress -= handler; }
    }
}
