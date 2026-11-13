// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Carthago.Services.SessionFiles;

namespace Carthago.Cli;

/// <summary>Read-only CLI boundary. No engine start, network access or trusted event ingestion.</summary>
public static class CliApplication
{
    public const int SchemaVersion = 1;
    public const int Success = 0;
    public const int UsageError = 2;
    public const int DataError = 3;
    public const int Cancelled = 130;

    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);
    private static string Version => typeof(CliApplication).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0]
        ?? "0.1.0";

    private const string Help = """
        CARTHAGO CLI — read-only offline companion

        Usage:
          carthago --help
          carthago --version [--json]
          carthago status [--json]
          carthago capabilities [--json]
          carthago session inspect <file.csa> [--json]

        status reports this CLI only, not the monitoring engine.
        session inspect verifies an existing CSA archive and reports category counts;
        imported data is untrusted and no raw rows are printed.
        Exit codes: 0 success, 2 usage, 3 data/runtime error, 130 cancelled.
        """;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error,
        CancellationToken token = default)
    {
        // Options are accepted only in the documented trailing position.
        if (args.Length == 0 || args is ["--help"] or ["-h"] or ["help"])
        {
            await output.WriteLineAsync(Help);
            return Success;
        }

        bool json = args[^1] == "--json";
        string[] command = json ? args[..^1] : args;

        try
        {
            token.ThrowIfCancellationRequested();
            switch (command)
            {
                case ["--version"]:
                    await WriteAsync(output, json, new { schemaVersion = SchemaVersion, version = Version },
                        $"carthago {Version}");
                    return Success;

                case ["status"]:
                    await WriteAsync(output, json, new
                    {
                        schemaVersion = SchemaVersion,
                        version = Version,
                        operatingSystem = OS(),
                        architecture = RuntimeInformation.ProcessArchitecture.ToString(),
                        runtime = RuntimeInformation.FrameworkDescription,
                        mode = "offline",
                        engineStatus = "unavailable",
                        engineReason = "No live engine connection is implemented."
                    }, $"CARTHAGO CLI {Version}\nOS: {OS()} ({RuntimeInformation.ProcessArchitecture})\n" +
                       $"Runtime: {RuntimeInformation.FrameworkDescription}\nMode: offline\n" +
                       "Monitoring engine: unavailable (not connected)");
                    return Success;

                case ["capabilities"]:
                    var capabilities = new[]
                    {
                        new Capability("session.inspect", "available", "Read-only CSA v1 integrity and category summary."),
                        new Capability("live.status", "unavailable", "No authenticated engine connection."),
                        new Capability("live.events", "unavailable", "No live event transport."),
                        new Capability("live.rules", "unavailable", "No live rule catalog connection."),
                        new Capability("live.incidents", "unavailable", "No live incident connection."),
                        new Capability("capture", "unavailable", "No CLI capture provider."),
                        new Capability("sensor.control", "unavailable", "No CLI sensor control provider.")
                    };
                    await WriteAsync(output, json, new { schemaVersion = SchemaVersion, capabilities },
                        string.Join("\n", capabilities.Select(c => $"{c.Name}: {c.State} — {c.Reason}")));
                    return Success;

                case ["session", "inspect", var path] when !string.IsNullOrWhiteSpace(path) && !path.StartsWith("--", StringComparison.Ordinal):
                    if (!string.Equals(Path.GetExtension(path), CarthagoSessionSnapshot.FileExtension,
                        StringComparison.OrdinalIgnoreCase))
                        return await FailAsync(error, json, UsageError, "invalid_usage", "Expected a .csa session file.");

                    // Existing archive reader verifies inventory, sizes, hashes and row counts.
                    // Hashes are integrity checks, not producer authentication.
                    var snapshot = await new CarthagoSessionArchiveService().OpenAsync(path, token);
                    token.ThrowIfCancellationRequested();
                    var categories = CarthagoSessionSnapshot.CategoryOrder
                        .Select(name => new CategoryCount(name, snapshot.Categories[name].Count)).ToArray();
                    await WriteAsync(output, json, new
                    {
                        schemaVersion = SchemaVersion,
                        archiveVersion = CarthagoSessionSnapshot.FormatVersion,
                        integrity = "verified",
                        provenance = "untrusted_import",
                        categories
                    }, "CSA v1: integrity verified (not authenticated)\n" +
                        "Source: untrusted imported session; counts are not live telemetry.\n" +
                        string.Join("\n", categories.Select(c => $"{c.Category}: {c.Count}")));
                    return Success;

                default:
                    return await FailAsync(error, json, UsageError, "invalid_usage", "Unknown command or arguments. Use --help.");
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            return await FailAsync(error, json, Cancelled, "cancelled", "Command cancelled.");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Never echo exception details or imported strings (paths, secrets, control characters).
            // Malformed archives may fail in the shared reader in several different ways.
            return await FailAsync(error, json, DataError, "data_or_runtime_error",
                "Command failed. Check file access and CSA format/integrity.");
        }
    }

    private static string OS() => OperatingSystem.IsWindows() ? "windows"
        : OperatingSystem.IsLinux() ? "linux" : OperatingSystem.IsMacOS() ? "macos" : "other";

    private static Task WriteAsync(TextWriter writer, bool json, object payload, string human)
        => writer.WriteLineAsync(json ? JsonSerializer.Serialize(payload, JsonOptions) : human);

    private static async Task<int> FailAsync(TextWriter error, bool json, int exitCode, string code, string message)
    {
        await WriteAsync(error, json, new { schemaVersion = SchemaVersion, error = code, message }, message);
        return exitCode;
    }

    private sealed record Capability(string Name, string State, string Reason);
    private sealed record CategoryCount(string Category, int Count);
}
