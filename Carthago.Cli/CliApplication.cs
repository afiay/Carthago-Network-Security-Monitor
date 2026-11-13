// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Carthago.Services.SessionFiles;
using Carthago.Contracts;

namespace Carthago.Cli;

/// <summary>Read-only CLI boundary. No engine start, remote network access or trusted event ingestion.</summary>
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
          carthago engine status [--json]
          carthago rules summary [--json]
          carthago rules list <file.csa> [--offset N --limit N] [--json]
          carthago rules show <file.csa> <rule-id> [--json]
          carthago rules quality <ledger.md> [--json]
          carthago session inspect <file.csa> [--json]

        status reports this CLI only, not the monitoring engine.
        Live queries require Windows and a WPF host started with --enable-cli-ipc.
        session inspect verifies an existing CSA archive and reports category counts;
        imported data is untrusted and no raw rows are printed.
        Exit codes: 0 success, 2 usage, 3 data/runtime error, 130 cancelled.
        """;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error,
        CancellationToken token = default,
        Func<ReadCommand, CancellationToken, Task<ReadResponse>>? query = null)
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
                        engineReason = "This command does not query the live host; use engine status."
                    }, $"CARTHAGO CLI {Version}\nOS: {OS()} ({RuntimeInformation.ProcessArchitecture})\n" +
                       $"Runtime: {RuntimeInformation.FrameworkDescription}\nMode: offline\n" +
                       "Monitoring engine: unavailable (not connected)");
                    return Success;

                case ["capabilities"]:
                    var capabilities = new[]
                    {
                        new Capability("session.inspect", "available", "Read-only CSA v1 integrity and category summary."),
                        new Capability("live.status", "unavailable", "Windows opt-in local query; use engine status to check connectivity."),
                        new Capability("live.events", "unavailable", "No live event transport."),
                        new Capability("live.rules", "unavailable", "Windows opt-in catalog query; use rules summary to check connectivity."),
                        new Capability("live.incidents", "unavailable", "No live incident connection."),
                        new Capability("capture", "unavailable", "No CLI capture provider."),
                        new Capability("sensor.control", "unavailable", "No CLI sensor control provider.")
                    };
                    await WriteAsync(output, json, new { schemaVersion = SchemaVersion, capabilities },
                        string.Join("\n", capabilities.Select(c => $"{c.Name}: {c.State} — {c.Reason}")));
                    return Success;

                case ["engine", "status"]:
                    return await LiveAsync(ReadCommand.HostStatus, output, error, json, token, query);
                case ["rules", "summary"]:
                    return await LiveAsync(ReadCommand.RulesSummary, output, error, json, token, query);

                case ["rules", "list", var listPath]:
                    return await ListRulesAsync(listPath, 0, 50, output, error, json, token);
                case ["rules", "list", var pagePath, "--offset", var offset, "--limit", var limit]:
                    if (!OfflineRuleQueries.TryPage(offset, limit, out int start, out int size))
                        return await FailAsync(error, json, UsageError, "invalid_usage", "Offset must be nonnegative; limit must be 1–100.");
                    return await ListRulesAsync(pagePath, start, size, output, error, json, token);
                case ["rules", "show", var rulePath, var ruleId]:
                    if (!IsCsaPath(rulePath) || !OfflineRuleQueries.IsRuleId(ruleId))
                        return await FailAsync(error, json, UsageError, "invalid_usage", "Expected a .csa file and uppercase numeric rule ID.");
                    var rule = await OfflineRuleQueries.ShowAsync(rulePath, ruleId, token);
                    if (rule is null) return await FailAsync(error, json, DataError, "rule_not_found", "Rule not found in the saved catalog.");
                    await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "untrusted_import",
                        validation = "not_assessed", rule }, $"{rule.RuleId} {rule.Name ?? "(name unavailable)"}\\nCategory: {rule.Category ?? "unavailable"}\\nDefault severity: {rule.DefaultSeverity ?? "unavailable"}\\nEnabled by default: {rule.EnabledByDefault?.ToString() ?? "unavailable"}\\nPlanned: {rule.IsPlanned?.ToString() ?? "unavailable"}\\nMaturity: {rule.Maturity ?? "unavailable"}\\nValidation: not assessed (saved catalog)");
                    return Success;
                case ["rules", "quality", var ledgerPath] when !string.IsNullOrWhiteSpace(ledgerPath) && !ledgerPath.StartsWith("--", StringComparison.Ordinal):
                    var quality = await OfflineRuleQueries.QualityAsync(ledgerPath, token);
                    await WriteAsync(output, json, new { schemaVersion = SchemaVersion, quality },
                        $"Ledger rows: {quality.LedgerRows}\\nAudit pending: {quality.AuditPending}\\nProducer-blocked labels: {quality.ProducerBlocked}\\nOther/unclassified: {quality.OtherOrUnclassified}\\nValidation: not assessed; provisional ledger, not live coverage.");
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
                "Command failed. Check file access and input format/integrity.");
        }
    }

    private static async Task<int> LiveAsync(ReadCommand command, TextWriter output, TextWriter error,
        bool json, CancellationToken token, Func<ReadCommand, CancellationToken, Task<ReadResponse>>? query)
    {
        if (query is null && !OperatingSystem.IsWindows())
            return await FailAsync(error, json, DataError, "unsupported_platform", "Live queries require Windows.");
        ReadResponse response;
        try
        {
            if (query is not null) response = await query(command, token);
            else if (OperatingSystem.IsWindows()) response = await WindowsLocalReadPipe.QueryAsync(command, token);
            else return await FailAsync(error, json, DataError, "unsupported_platform", "Live queries require Windows.");
        }
        catch (Exception ex) when (ex is not OutOfMemoryException && !token.IsCancellationRequested)
        {
            return await FailAsync(error, json, DataError, "engine_unavailable",
                "Local endpoint unavailable. Start WPF with --enable-cli-ipc using the same account and elevation.");
        }
        token.ThrowIfCancellationRequested();
        if (response.State != ReadState.Available)
            return await FailAsync(error, json, DataError, "source_unavailable", "Host could not provide the requested data.");
        if (command == ReadCommand.HostStatus)
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, hostStatus = "reachable",
                engineHealth = "not_assessed", provenance = "same_user_local_endpoint", observedUtc = response.ObservedUtc },
                "Local CARTHAGO host: reachable\\nDetection engine health: not assessed");
        else
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "same_user_local_endpoint",
                observedUtc = response.ObservedUtc, registered = response.Registered,
                enabledByDefault = response.EnabledByDefault, planned = response.Planned, validation = "not_assessed" },
                $"Registered: {response.Registered}\\nEnabled by default: {response.EnabledByDefault}\\nPlanned: {response.Planned}\\nValidation: not assessed");
        return Success;
    }

    private static bool IsCsaPath(string path) => !string.IsNullOrWhiteSpace(path)
        && !path.StartsWith("--", StringComparison.Ordinal)
        && string.Equals(Path.GetExtension(path), ".csa", StringComparison.OrdinalIgnoreCase);

    private static async Task<int> ListRulesAsync(string path, int offset, int limit, TextWriter output,
        TextWriter error, bool json, CancellationToken token)
    {
        if (!IsCsaPath(path)) return await FailAsync(error, json, UsageError, "invalid_usage", "Expected a .csa file.");
        var page = await OfflineRuleQueries.ListAsync(path, offset, limit, token);
        await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "untrusted_import",
            validation = "not_assessed", page },
            $"Saved catalog: {page.Total} rows (offset {page.Offset}, limit {page.Limit})\\n" +
            string.Join("\\n", page.Rules.Select(r => $"{r.RuleId} {r.Name ?? "(name unavailable)"}")));
        return Success;
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
