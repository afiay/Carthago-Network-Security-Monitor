// SPDX-License-Identifier: MIT
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using Carthago.Contracts;
using Carthago.Services;
using Carthago.Services.Sensors;
using SharpPcap;

namespace Carthago.ActiveQualification;

// Explicit interactive physical lab; never writes production evidence or grants.
internal static class LiveSensorLab
{
    private sealed record Request(string Sensor, Guid AdapterId, IPAddress Source, IPAddress Target, string Expected);

    private static bool CanonicalIpv4(string text, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (!IPAddress.TryParse(text, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetwork ||
            parsed.ToString() != text || !LocalLanDiscovery.IsLocalHostAddress(parsed)) return false;
        ip = parsed; return true;
    }

    private static bool ValidOid(string text)
    {
        if (text.Length is < 3 or > 128) return false;
        var parts = text.Split('.');
        if (parts.Length is < 2 or > 32) return false;
        var numbers = new uint[parts.Length];
        for (int i = 0; i < parts.Length; i++)
            if (parts[i].Length == 0 || parts[i].Any(c => c is < '0' or > '9') ||
                (parts[i].Length > 1 && parts[i][0] == '0') ||
                !uint.TryParse(parts[i], System.Globalization.NumberStyles.None,
                    System.Globalization.CultureInfo.InvariantCulture, out numbers[i])) return false;
        return numbers[0] <= 2 && (numbers[0] == 2 || numbers[1] <= 39);
    }

    private static Request? Parse(string[] args)
    {
        if (args is not ["live", var sensor, "--adapter", var id, "--source", var source,
            "--target", var target, "--expected", var expected] || sensor is not ("gateway" or "snmp") ||
            !Guid.TryParseExact(id, "D", out var adapter) || adapter == Guid.Empty ||
            !CanonicalIpv4(source, out var src) || !CanonicalIpv4(target, out var dst) || src.Equals(dst)) return null;
        if (sensor == "gateway")
        {
            var mac = GatewayIntegritySensor.NormalizeMac(expected);
            if (mac is null) return null;
            expected = mac;
        }
        else if (!ValidOid(expected)) return null;
        return new(sensor, adapter, src, dst, expected);
    }

    private static LocalLanInterface? Resolve(Request request)
    {
        var candidates = LocalLanDiscovery.GetLocalInterfaces(request.AdapterId)
            .Where(a => a.Address.Equals(request.Source) &&
                LocalLanDiscovery.PlanProbeTargets(new[] { a }).Contains(request.Target)).ToArray();
        return candidates.Length == 1 ? candidates[0] : null;
    }

    private static bool SameScope(Request request, LocalLanInterface initial) =>
        Resolve(request) is { } current && current.Mask.Equals(initial.Mask);

    // No command-line, environment or redirected-input credentials.
    private static string ReadField(string prompt, bool secret, int max, CancellationToken token)
    {
        Console.Error.Write(prompt);
        var chars = new char[max];
        int count = 0;
        try
        {
            while (true)
            {
                token.ThrowIfCancellationRequested();
                if (!Console.KeyAvailable) { Thread.Sleep(50); continue; }
                var key = Console.ReadKey(intercept: true);
                if (key.Key == ConsoleKey.Escape) throw new OperationCanceledException();
                if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); return new string(chars, 0, count); }
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (count > 0) { chars[--count] = '\0'; if (!secret) Console.Error.Write("\b \b"); }
                    continue;
                }
                if (key.KeyChar < 32 || key.KeyChar > 126) continue;
                if (count == max) throw new ArgumentException("Input too long.");
                chars[count++] = key.KeyChar;
                if (!secret) Console.Error.Write(key.KeyChar);
            }
        }
        finally { Array.Clear(chars); }
    }

    private static int Report(string sensor, string result, string outcome, bool? expectedMatch = null,
        int? observedFields = null)
    {
        Console.WriteLine(JsonSerializer.Serialize(new { schemaVersion = 1, mode = "physical-lab",
            sensor, result, outcome, expectedMatch, observedFields, productionEvidenceWritten = false }));
        return result == "Passed" ? 0 : result == "Inconclusive" ? 3 : 1;
    }

    private static string GatewayResult(GatewayIntegrityObservation observed) =>
        observed.Status == GatewayIntegrityStatus.BaselineMatch && observed.DirectMacs.Count == 1 &&
            !observed.ClaimLimitReached && !observed.CacheDiffers ? "Passed" :
        observed.Status == GatewayIntegrityStatus.NoReply ? "Inconclusive" : "Failed";

    private static string SnmpResult(SnmpInfrastructureObservation observed, string expected) =>
        observed.Status == SnmpInfrastructureStatus.Observed && observed.Evidence?.ObjectId == expected ? "Passed" :
        observed.Status is SnmpInfrastructureStatus.Partial or SnmpInfrastructureStatus.TimedOut or
            SnmpInfrastructureStatus.TransportError ? "Inconclusive" : "Failed";

    internal static async Task<int> RunAsync(string[] args)
    {
        var request = Parse(args);
        if (request is null)
        {
            Console.Error.WriteLine("Usage: live gateway|snmp --adapter GUID --source IPv4 --target IPv4 --expected MAC|OID");
            return 2;
        }
        if (!OperatingSystem.IsWindows() || Console.IsInputRedirected)
            return Report(request.Sensor, "Inconclusive", "InteractiveWindowsConsoleRequired");
        using var cancellation = new CancellationTokenSource();
        ConsoleCancelEventHandler cancel = (_, e) => { e.Cancel = true; cancellation.Cancel(); };
        Console.CancelKeyPress += cancel;
        try
        {
            var adapter = Resolve(request);
            if (adapter is null) return Report(request.Sensor, "Inconclusive", "ScopeUnavailableOrAmbiguous");
            if (request.Sensor == "gateway" && !GatewayIntegritySensor.IsConfiguredGateway(request.AdapterId, adapter, request.Target))
                return Report(request.Sensor, "Inconclusive", "NotConfiguredGateway");
            Console.Error.WriteLine($"Physical {request.Sensor} qualification: adapter {request.AdapterId:D}, " +
                $"source {request.Source}/{adapter.Mask}, target {request.Target}, expected {request.Expected}.");
            Console.Error.WriteLine("One bounded read-only check. Confirm that you control or have permission to test this target.");
            if (ReadField("Type PROBE to authorize: ", false, 16, cancellation.Token) != "PROBE")
                return Report(request.Sensor, "Inconclusive", "NotAuthorized");

            SnmpCredential? secret = null;
            if (request.Sensor == "snmp")
                secret = new SnmpCredential(ReadField("SNMPv3 username: ", true, 32, cancellation.Token),
                    ReadField("Authentication passphrase: ", true, 128, cancellation.Token),
                    ReadField("Privacy passphrase: ", true, 128, cancellation.Token));

            cancellation.Token.ThrowIfCancellationRequested();
            using var lease = WindowsActiveSchedulerReservation.Acquire();
            if (!SameScope(request, adapter))
                return Report(request.Sensor, "Inconclusive", "ScopeChanged");
            if (request.Sensor == "gateway")
            {
                var devices = CaptureDeviceList.Instance.OfType<ILiveDevice>()
                    .Where(d => CaptureDeviceLabelFormatter.ParseDeviceGuid(d.Name) == request.AdapterId).ToArray();
                if (devices.Length != 1) return Report(request.Sensor, "Inconclusive", "NpcapAdapterUnavailableOrAmbiguous");
                var result = await GatewayIntegritySensor.CheckAuthorizedAsync(devices[0], adapter, request.Target,
                    request.Expected, () => SameScope(request, adapter), cancellation.Token);
                return Report("gateway", GatewayResult(result), result.Status.ToString(),
                    result.DirectMacs.Count == 1 ? result.Status == GatewayIntegrityStatus.BaselineMatch : null,
                    result.DirectMacs.Count);
            }

            var observation = await SnmpInfrastructureSensor.CheckAsync(adapter, request.Target,
                secret!.User, secret.Authentication, secret.Privacy, cancellation.Token);
            if (!SameScope(request, adapter)) return Report("snmp", "Inconclusive", "ScopeChanged");
            var e = observation.Evidence;
            int fields = e is null ? 0 : new[] { e.Description is not null, e.ObjectId is not null,
                e.UptimeCentiseconds.HasValue, e.Name is not null, e.InterfaceCount.HasValue }.Count(x => x);
            return Report("snmp", SnmpResult(observation, request.Expected), observation.Status.ToString(),
                e?.ObjectId is null ? null : e.ObjectId == request.Expected, fields);
        }
        catch (OperationCanceledException) { Report(request.Sensor, "Inconclusive", "Cancelled"); return 130; }
        catch (CaptureReservationUnavailableException) { return Report(request.Sensor, "Inconclusive", "CaptureReservationUnavailable"); }
        catch (GatewayScopeChangedException) { return Report(request.Sensor, "Inconclusive", "ScopeChanged"); }
        catch (ArgumentException) { return Report(request.Sensor, "Failed", "InvalidInput"); }
        catch (InvalidOperationException) { return Report(request.Sensor, "Inconclusive", "OperationUnavailable"); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        { return Report(request.Sensor, "Inconclusive", "NativeOrEnvironmentFailure"); }
        finally { Console.CancelKeyPress -= cancel; }
    }

    // Offline contract checks: no console input, network or production database.
    internal static int VerifyContract()
    {
        string[] Valid(string sensor, string expected) => new[] { "live", sensor, "--adapter",
            "02702701-1234-4321-9999-000000000001", "--source", "192.168.50.10",
            "--target", "192.168.50.1", "--expected", expected };
        var gateway = Parse(Valid("gateway", "02:00:00:00:00:01"));
        var snmp = Parse(Valid("snmp", "1.3.6.1.4.1.9"));
        if (gateway is null || snmp is null || Parse(Valid("gateway", "ff:ff:ff:ff:ff:ff")) is not null ||
            Parse(Valid("snmp", "1.40.3")) is not null || Parse(Valid("snmp", "1.03.6")) is not null ||
            Parse(Valid("snmp", "1.3.6").Concat(new[] { "--password", "secret" }).ToArray()) is not null) return 1;
        var bad = Valid("snmp", "1.3.6"); bad[7] = "8.8.8.8";
        if (Parse(bad) is not null) return 1;
        var good = GatewayIntegritySensor.Evaluate(gateway.Source, gateway.Target,
            new[] { gateway.Expected }, gateway.Expected, gateway.Expected);
        var noReply = GatewayIntegritySensor.Evaluate(gateway.Source, gateway.Target, Array.Empty<string>(), null, gateway.Expected);
        if (GatewayResult(good) != "Passed" || GatewayResult(noReply) != "Inconclusive" ||
            GatewayResult(good with { CacheDiffers = true }) != "Failed") return 1;
        var observation = new SnmpInfrastructureObservation(snmp.Source, snmp.Target, SnmpInfrastructureStatus.Observed,
            new("description", snmp.Expected, 100, "name", 2), DateTimeOffset.UtcNow, TimeSpan.Zero);
        if (SnmpResult(observation, snmp.Expected) != "Passed" || SnmpResult(observation, "1.3.6") != "Failed" ||
            SnmpResult(observation with { Status = SnmpInfrastructureStatus.Partial }, snmp.Expected) != "Inconclusive") return 1;
        Console.WriteLine("PASS AS-Q07G4 offline live-lab contract");
        return 0;
    }
}
