// SPDX-License-Identifier: MIT
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using Carthago.Services.SessionFiles;
using Carthago.Contracts;
using Carthago.Engine.Rules;

namespace Carthago.Cli;

/// <summary>Local CLI; read queries and explicit session-scoped foreground stop only.</summary>
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
        CARTHAGO CLI — local monitoring companion

        Usage:
          carthago --help
          carthago --version [--json]
          carthago status [--json]
          carthago capabilities [--json]
          carthago capture doctor [--json]
          carthago capture interfaces [--json]
          carthago engine status [--json]
          carthago monitor status [--json]
          carthago service status|health|start|stop|doctor [--json]
          carthago engine health [--json]
          carthago monitor stop [--session GUID] [--json]
          carthago rules summary [--json]
          carthago rules capabilities [--portable|RULE_ID] [--json]
          carthago rules list --live [--offset N --limit N] [--json]
          carthago rules show <rule-id> --live [--json]
          carthago rules validate [--json]
          carthago sensors list [--offset N --limit N] [--json]
          carthago sensors health [--json]
          carthago rules list <file.csa> [--offset N --limit N] [--json]
          carthago rules show <file.csa> <rule-id> [--json]
          carthago rules quality <ledger.md> [--json]
          carthago session inspect <file.csa> [--json]
          carthago pcap inspect <file.pcap|file.pcapng> [--limit N] [--json]
          carthago pcap detect <file.pcap|file.pcapng> --rules R586[,R...] [--limit N] [--json]
          carthago alerts list <file.csa|--live> [--severity LEVEL] [--source-ip IP] [--offset N] [--limit N] [--json]
          carthago alerts show <file.csa|--live> <event-id> [--json]
          carthago alerts list --live [--date YYYY-MM-DD | --since 1h] [--json]
          carthago alerts tail --live [--severity LEVEL] [--source-ip IP] [--json]
          carthago incidents list <file.csa|--live> [--severity LEVEL] [--source-ip IP] [--offset N] [--limit N] [--json]
          carthago incidents show <file.csa|--live> <incident-id> [--json]
          carthago events list <file.csa|--live> [--source-ip IP] [--offset N] [--limit N] [--json]
          carthago hosts list <file.csa|--live> [--source-ip IP] [--offset N] [--limit N] [--json]

        status reports this CLI only, not the monitoring engine.
        Live queries require Windows and an IPC-enabled desktop or foreground host.
        Monitor stop requires foreground --allow-cli-stop (in addition to --enable-cli-ipc).
        session inspect verifies an existing CSA archive and reports category counts;
        imported data is untrusted and no raw rows are printed.
        Exit codes: 0 success, 2 usage, 3 data/runtime error, 130 cancelled.
        """;

    public static async Task<int> RunAsync(string[] args, TextWriter output, TextWriter error,
        CancellationToken token = default,
        Func<ReadCommand, CancellationToken, Task<ReadResponse>>? query = null,
        Func<LiveQuery, CancellationToken, Task<LiveQueryResult>>? liveQuery = null,
        Func<InvestigationRequest, CancellationToken, Task<InvestigationResponse>>? investigationQuery = null,
        Func<MonitorControlRequest, CancellationToken, Task<MonitorControlResponse>>? monitorQuery = null)
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
            if (command is ["alerts", "tail", ..])
                return await TailAsync(command, output, error, json, token, investigationQuery);
            if (command.Length > 0 && (command[0] is "alerts" or "incidents" or "events" or "hosts"))
                return await InvestigateAsync(command, output, error, json, token, investigationQuery);
            if (command is ["capture", ..])
            {
                if (command is not (["capture", "doctor"] or ["capture", "interfaces"]))
                    return await FailAsync(error, json, UsageError, "invalid_usage",
                        "Expected capture doctor|interfaces [--json].");
                var discovery = NativeCaptureDiscovery.Discover();
                token.ThrowIfCancellationRequested();
                await WriteAsync(output, json, new { schemaVersion = SchemaVersion, mode = "discovery_only",
                    discovery.Provider, discovery.LibraryStatus, discovery.LibraryVersion,
                    discovery.EnumerationStatus, discovery.Reason, discovery.Interfaces,
                    capturePermission = "not_assessed", liveCapture = "not_implemented",
                    detectionValidation = "not_assessed" },
                    $"Capture provider: {discovery.Provider}; library: {discovery.LibraryStatus}; enumeration: {discovery.EnumerationStatus}.\n" +
                    "Capture permission not assessed; live capture not implemented.\n" +
                    string.Join("\n", discovery.Interfaces.Select(i => $"{i.Id} | loopback={i.Loopback}")));
                return Success;
            }
            if (command is ["rules", "capabilities", ..])
            {
                if (command.Length > 3 || (command.Length == 3 && command[2] != "--portable" &&
                    (command[2] != command[2].Trim() || !RuleIdValidator.IsCoreRuleId(command[2]))))
                    return await FailAsync(error, json, UsageError, "invalid_usage",
                        "Expected rules capabilities [--portable|RULE_ID] [--json].");
                var rows = command.Length == 3 && command[2] != "--portable"
                    ? new[] { PortableRuleCatalog.Describe(command[2]) }
                    : PortableRuleCatalog.All.ToArray();
                await WriteAsync(output, json, new { schemaVersion = SchemaVersion,
                    scope = "compiled_portable_catalog", registration = "not_assessed",
                    detectionValidation = "not_assessed", supportedCount = PortableRuleCatalog.All.Count, rules = rows },
                    "Compiled portable catalog only; live registration and detection validation not assessed.\n" +
                    string.Join("\n", rows.Select(r => $"{r.RuleId}: {r.Status} {r.Name} | {string.Join(",", r.ExecutionEnvironments)} | qualification={r.Qualification}" +
                        (r.Reason is null ? "" : $" | {r.Reason}"))));
                return Success;
            }
            if (command is ["pcap", "detect", ..])
            {
                if (!PcapDetectCommand.TryParse(command, out var path, out var rules, out var limit))
                    return await FailAsync(error, json, UsageError, "invalid_usage",
                        "Expected pcap detect <file.pcap|file.pcapng> --rules R586[,R...] [--limit 1-100] [--json].");
                var replay = await PcapDetectCommand.RunAsync(path, rules, limit, token);
                await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "untrusted_capture",
                    mode = "offline_replay", detectionValidation = "not_assessed", replay },
                    $"Offline replay: {replay.PacketsRead} packets; {replay.Parsed} parsed; {replay.MatchCount} observations; {replay.SuppressedCount} suppressed.\n" +
                    string.Join("\n", replay.Rules.Select(r => $"{r.RuleId}: {r.Status}; evaluated={r.Evaluated}; matches={r.Matches}")) +
                    "\nUntrusted observations only; no live alert publication.\n" +
                    string.Join("\n", replay.Findings.Select(f => $"{f.RuleId} packet={f.PacketNumber} {f.TimestampUtc:O} {f.Method}")));
                return Success;
            }
            if (command.Length > 0 && command[0] == "pcap")
            {
                if (!PcapInspectCommand.TryParse(command, out var pcapPath, out var pcapLimit))
                    return await FailAsync(error, json, UsageError, "invalid_usage", "Expected pcap inspect <file.pcap|file.pcapng> [--limit 1-100] [--json].");
                var capture = await PcapInspectCommand.InspectAsync(pcapPath, pcapLimit, token);
                await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "untrusted_capture",
                    detectionValidation = "not_assessed", capture },
                    $"{capture.Format.ToUpperInvariant()}: {capture.PacketsRead} packets; parsed {capture.Parsed}; rejected {capture.Rejected}; capture-truncated {capture.CaptureTruncated}.\n" +
                    $"Link type: {capture.LinkLayerType?.ToString() ?? "per-interface"}; timestamps: {capture.TimestampResolution}; clock resets: {capture.ClockResets}.\n" +
                    $"Untrusted capture; detection rules not executed. Sample: {capture.Rows.Count}/{capture.Parsed}.\n" +
                    string.Join("\n", capture.Rows.Select(r => $"{r.PacketNumber} {r.TimestampUtc:O} {r.Source}:{r.SourcePort} -> {r.Destination}:{r.DestinationPort} {r.Protocol} {r.ApplicationProtocol}")));
                return Success;
            }
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
                        new Capability("capture", "unavailable", "No CLI live capture provider."),
                        new Capability("capture.discovery", "available", "Read-only provider discovery; no capture handle opened."),
                        new Capability("pcap.inspect", "available", "Read-only classic PCAP and PCAPNG enhanced-packet telemetry; no rule execution."),
                        new Capability("pcap.detect", "available", "Offline portable request observations; see rules capabilities for supported IDs."),
                        new Capability("rules.capabilities", "available", "Compiled portable detector catalog; not live registration or validation."),
                        new Capability("sensor.control", "unavailable", "No CLI sensor control provider.")
                    };
                    await WriteAsync(output, json, new { schemaVersion = SchemaVersion, capabilities },
                        string.Join("\n", capabilities.Select(c => $"{c.Name}: {c.State} — {c.Reason}")));
                    return Success;

                case ["service", var serviceAction] when serviceAction is "status" or "health" or "start" or "stop" or "doctor":
                    if (!OperatingSystem.IsWindows())
                        return await FailAsync(error, json, DataError, "unsupported_platform", "Windows SCM required.");
                    return await ServiceCommands.RunAsync(serviceAction, new WindowsServiceControl(), output, error, json, token);
                case ["monitor", "status"]:
                    return await MonitorAsync(false, null, output, error, json, token, monitorQuery);
                case ["engine", "health"]:
                    return await MonitorAsync(false, null, output, error, json, token, monitorQuery, detailed: true);
                case ["monitor", "stop"]:
                    return await MonitorAsync(true, null, output, error, json, token, monitorQuery);
                case ["monitor", "stop", "--session", var sessionId]:
                    if (!Guid.TryParseExact(sessionId, "D", out var target) || target == Guid.Empty)
                        return await FailAsync(error, json, UsageError, "invalid_usage", "Expected a nonempty session GUID.");
                    return await MonitorAsync(true, target, output, error, json, token, monitorQuery);
                case ["engine", "status"]:
                    return await LiveAsync(ReadCommand.HostStatus, output, error, json, token, query);
                case ["rules", "summary"]:
                    return await LiveAsync(ReadCommand.RulesSummary, output, error, json, token, query);

                case ["rules", "list", "--live"]:
                    return await QueryV2Async(LiveQueryKind.RulesList, 0, 50, null, output, error, json, token, liveQuery);
                case ["rules", "list", "--live", "--offset", var liveOffset, "--limit", var liveLimit]:
                    if (!OfflineRuleQueries.TryPage(liveOffset, liveLimit, out int liveStart, out int liveSize))
                        return await FailAsync(error, json, UsageError, "invalid_usage", "Offset must be nonnegative; limit must be 1–100.");
                    return await QueryV2Async(LiveQueryKind.RulesList, liveStart, liveSize, null, output, error, json, token, liveQuery);
                case ["rules", "show", var liveId, "--live"]:
                    if (!LiveQueryProtocol.RuleIdValid(liveId))
                        return await FailAsync(error, json, UsageError, "invalid_usage", "Expected uppercase numeric rule ID.");
                    return await QueryV2Async(LiveQueryKind.RuleShow, 0, 1, liveId, output, error, json, token, liveQuery);
                case ["rules", "validate"]:
                    return await QueryV2Async(LiveQueryKind.RulesValidate, 0, 1, null, output, error, json, token, liveQuery);
                case ["sensors", "list"]:
                    return await QueryV2Async(LiveQueryKind.SensorsList, 0, 50, null, output, error, json, token, liveQuery);
                case ["sensors", "list", "--offset", var sensorOffset, "--limit", var sensorLimit]:
                    if (!OfflineRuleQueries.TryPage(sensorOffset, sensorLimit, out int sensorStart, out int sensorSize))
                        return await FailAsync(error, json, UsageError, "invalid_usage", "Offset must be nonnegative; limit must be 1–100.");
                    return await QueryV2Async(LiveQueryKind.SensorsList, sensorStart, sensorSize, null, output, error, json, token, liveQuery);
                case ["sensors", "health"]:
                    return await QueryV2Async(LiveQueryKind.SensorsHealth, 0, 1, null, output, error, json, token, liveQuery);

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
                        validation = "not_assessed", rule }, $"{rule.RuleId} {rule.Name ?? "(name unavailable)"}\nCategory: {rule.Category ?? "unavailable"}\nDefault severity: {rule.DefaultSeverity ?? "unavailable"}\nEnabled by default: {rule.EnabledByDefault?.ToString() ?? "unavailable"}\nPlanned: {rule.IsPlanned?.ToString() ?? "unavailable"}\nMaturity: {rule.Maturity ?? "unavailable"}\nValidation: not assessed (saved catalog)");
                    return Success;
                case ["rules", "quality", var ledgerPath] when !string.IsNullOrWhiteSpace(ledgerPath) && !ledgerPath.StartsWith("--", StringComparison.Ordinal):
                    var quality = await OfflineRuleQueries.QualityAsync(ledgerPath, token);
                    await WriteAsync(output, json, new { schemaVersion = SchemaVersion, quality },
                        $"Ledger rows: {quality.LedgerRows}\nAudit pending: {quality.AuditPending}\nProducer-blocked labels: {quality.ProducerBlocked}\nOther/unclassified: {quality.OtherOrUnclassified}\nValidation: not assessed; provisional ledger, not live coverage.");
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
                "Local endpoint unavailable. Start desktop or foreground monitor with --enable-cli-ipc using the same account and elevation.");
        }
        token.ThrowIfCancellationRequested();
        if (response.State != ReadState.Available)
            return await FailAsync(error, json, DataError, "source_unavailable", "Host could not provide the requested data.");
        if (command == ReadCommand.HostStatus)
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, hostStatus = "reachable",
                engineHealth = "not_assessed", provenance = "same_user_local_endpoint", observedUtc = response.ObservedUtc },
                "Local CARTHAGO host: reachable\nDetection engine health: not assessed");
        else
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "same_user_local_endpoint",
                observedUtc = response.ObservedUtc, registered = response.Registered,
                enabledByDefault = response.EnabledByDefault, planned = response.Planned, validation = "not_assessed" },
                $"Registered: {response.Registered}\nEnabled by default: {response.EnabledByDefault}\nPlanned: {response.Planned}\nValidation: not assessed");
        return Success;
    }

    private static async Task<int> QueryV2Async(LiveQueryKind kind, int offset, int limit, string? id,
        TextWriter output, TextWriter error, bool json, CancellationToken token,
        Func<LiveQuery, CancellationToken, Task<LiveQueryResult>>? query)
    {
        var request = new LiveQuery(LiveQueryProtocol.Version, Guid.NewGuid(), kind, offset, limit, id);
        if (query is null && !OperatingSystem.IsWindows())
            return await FailAsync(error, json, DataError, "unsupported_platform", "Live queries require Windows.");
        LiveQueryResult response;
        try
        {
            if (query is not null) response = await query(request, token);
            else if (OperatingSystem.IsWindows()) response = await WindowsLocalReadPipe.QueryLiveAsync(request, token);
            else return await FailAsync(error, json, DataError, "unsupported_platform", "Live queries require Windows.");
            LiveQueryProtocol.ValidateResult(response, request);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException && !token.IsCancellationRequested)
        {
            return await FailAsync(error, json, DataError, "engine_unavailable", "Local v2 query endpoint unavailable or invalid.");
        }
        token.ThrowIfCancellationRequested();
        if (response.State == LiveQueryState.NotFound)
            return await FailAsync(error, json, DataError, "rule_not_found", "Rule not found in the live catalog.");
        if (response.State != LiveQueryState.Available)
            return await FailAsync(error, json, DataError, "source_unavailable", "Host data unavailable; no zero-count inference.");
        const string provenance = "same_user_local_endpoint";
        if (kind is LiveQueryKind.RulesList or LiveQueryKind.RuleShow)
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance, response.ObservedUtc,
                total = response.Total, offset, limit, rules = response.Rules, validation = "not_assessed" },
                $"Live registered catalog: {response.Total} matching rows (offset {offset}, limit {limit})\n" +
                string.Join("\n", response.Rules!.Select(r => $"{r.RuleId} {r.Name} | {r.Category} | {r.DefaultSeverity} | default enabled: {r.EnabledByDefault} | planned: {r.Planned}")) +
                "\nDetection validation: not assessed");
        else if (kind == LiveQueryKind.RulesValidate)
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance, response.ObservedUtc,
                catalogErrors = response.CatalogErrors, catalogIntegrity = response.CatalogErrors == 0 ? "passed" : "failed",
                detectionValidation = "not_assessed" },
                $"Catalog integrity errors: {response.CatalogErrors}\nDetection validation: not assessed");
        else if (kind == LiveQueryKind.SensorsList)
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance, response.ObservedUtc,
                total = response.Total, offset, limit, sensors = response.Sensors, lookbackDays = 7,
                heartbeatTrust = "unverified_journal", sensorHealth = "not_assessed" },
                $"Stored sensor heartbeat IDs: {response.Total} (7-day journal window)\n" +
                string.Join("\n", response.Sensors!.Select(s => $"{s.SensorId} {s.LastHeartbeatUtc:O} {s.Freshness}")) +
                "\nSensor runtime health: not assessed");
        else
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance, response.ObservedUtc,
                total = response.Total, fresh = response.Fresh, stale = response.Stale, future = response.Future,
                lookbackDays = 7, freshnessSeconds = 300, futureToleranceSeconds = 30,
                heartbeatTrust = "unverified_journal", sensorHealth = "not_assessed" },
                $"Stored heartbeat IDs: {response.Total}\nFresh: {response.Fresh}\nStale: {response.Stale}\nFuture: {response.Future}\nSensor runtime health: not assessed");
        return kind == LiveQueryKind.RulesValidate && response.CatalogErrors != 0 ? DataError : Success;
    }

    private static async Task<int> InvestigateAsync(string[] command, TextWriter output, TextWriter error,
        bool json, CancellationToken token, Func<InvestigationRequest, CancellationToken, Task<InvestigationResponse>>? query)
    {
        if (!InvestigationCommand.TryParse(command, out var kind, out string path, out var filter, out bool show))
            return await FailAsync(error, json, UsageError, "invalid_usage", "Invalid investigation command. Use --help.");
        if (path == "--live")
            return await InvestigateLiveAsync(kind, filter, show, output, error, json, token, query);
        var page = await InvestigationQueries.ReadAsync(path, kind, filter, token);
        if (show && page.Total == 0)
            return await FailAsync(error, json, DataError, "record_not_found", "Record not found in saved session.");
        string category = kind.ToString().ToLowerInvariant();
        string human = $"Saved {category}: {page.Total} matching rows; {page.OmittedRows} omitted; not live or complete history.\n" +
            string.Join("\n", page.Rows.Select(r =>
                $"{r.Id ?? "-"} | {r.ObservedUtc?.ToString("O") ?? "-"} | {r.RuleId ?? "-"} | {r.Severity ?? "-"} | {r.SourceIp ?? "-"} -> {r.DestinationIp ?? "-"} | {r.Protocol ?? "-"} | {r.Status ?? "-"}"));
        await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "untrusted_import",
            source = "saved_session", coverage = "retained_snapshot_not_complete_history", category, page }, human);
        return Success;
    }

    private static async Task<int> InvestigateLiveAsync(InvestigationKind kind, InvestigationFilter filter, bool show,
        TextWriter output, TextWriter error, bool json, CancellationToken token,
        Func<InvestigationRequest, CancellationToken, Task<InvestigationResponse>>? query)
    {
        if (query is null && !OperatingSystem.IsWindows())
            return await FailAsync(error, json, DataError, "unsupported_platform", "Live queries require Windows.");
        var request = new InvestigationRequest(InvestigationProtocol.Version, Guid.NewGuid(), kind, filter);
        InvestigationResponse response;
        try
        {
            if (query is not null) response = await query(request, token);
            else if (OperatingSystem.IsWindows()) response = await WindowsLocalReadPipe.QueryInvestigationAsync(request, token);
            else return await FailAsync(error, json, DataError, "unsupported_platform", "Live queries require Windows.");
            InvestigationProtocol.ValidateResponse(response, request);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException && !token.IsCancellationRequested)
        {
            return await FailAsync(error, json, DataError, "engine_unavailable", "Local v3 investigation endpoint unavailable or invalid.");
        }
        token.ThrowIfCancellationRequested();
        if (response.State != LiveQueryState.Available)
            return await FailAsync(error, json, DataError, "source_unavailable", "Requested source unavailable; no zero-count inference.");
        var page = response.Page!;
        if (show && page.Total == 0)
            return await FailAsync(error, json, DataError, "record_not_found", "Record not found in the bounded source.");
        bool historical = filter.JournalDate is not null || filter.SinceMinutes is not null;
        string source = historical ? "bounded_detection_journal_window" : InvestigationProtocol.Source(kind);
        JournalWindow? window = historical ? JournalWindow.Resolve(filter, response.ObservedUtc) : null;
        await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "same_user_local_endpoint",
            source, coverage = "bounded_source_not_complete_history", response.ObservedUtc, window, page },
            $"Source: {source}; {page.Total} matching rows; {page.OmittedRows} omitted; not complete history.\n" +
            string.Join("\n", page.Rows.Select(r =>
                $"{r.Id ?? "-"} | {r.ObservedUtc?.ToString("O") ?? "-"} | {r.RuleId ?? "-"} | {r.Severity ?? "-"} | {r.SourceIp ?? "-"} -> {r.DestinationIp ?? "-"} | {r.Protocol ?? "-"} | {r.Status ?? "-"}")));
        return Success;
    }

    private static async Task<int> TailAsync(string[] command, TextWriter output, TextWriter error, bool json,
        CancellationToken token, Func<InvestigationRequest, CancellationToken, Task<InvestigationResponse>>? query)
    {
        if (!AlertTail.TryParse(command, out var filter))
            return await FailAsync(error, json, UsageError, "invalid_usage", "Invalid tail command. Use --help.");
        if (query is null && !OperatingSystem.IsWindows())
            return await FailAsync(error, json, DataError, "unsupported_platform", "Live queries require Windows.");
        if (query is null)
            query = (request, ct) => OperatingSystem.IsWindows()
                ? WindowsLocalReadPipe.QueryInvestigationAsync(request, ct)
                : Task.FromException<InvestigationResponse>(new PlatformNotSupportedException());
        try
        {
            await AlertTail.RunAsync(filter, output, query, json, token);
            return Success;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException && !token.IsCancellationRequested)
        {
            return await FailAsync(error, json, DataError, "tail_interrupted",
                "Tail interrupted: journal unavailable, changed, UTC day changed or endpoint failed. Restart to replay the current day.");
        }
    }

    private static async Task<int> MonitorAsync(bool stop, Guid? target, TextWriter output, TextWriter error,
        bool json, CancellationToken token, Func<MonitorControlRequest, CancellationToken, Task<MonitorControlResponse>>? query, bool detailed = false)
    {
        if (query is null && !OperatingSystem.IsWindows())
            return await FailAsync(error, json, DataError, "unsupported_platform", "Monitor control requires Windows.");
        query ??= (request, ct) => OperatingSystem.IsWindows()
            ? WindowsLocalReadPipe.QueryMonitorAsync(request, ct)
            : Task.FromException<MonitorControlResponse>(new PlatformNotSupportedException());
        async Task<MonitorControlResponse> Send(MonitorControlKind kind, Guid? id)
        {
            var request = new MonitorControlRequest(MonitorControlProtocol.Version, Guid.NewGuid(), kind, id);
            var response = await query(request, token);
            MonitorControlProtocol.ValidateResponse(response, request);
            token.ThrowIfCancellationRequested();
            return response;
        }
        try
        {
            MonitorControlResponse result;
            if (!stop) result = await Send(detailed ? MonitorControlKind.Health : MonitorControlKind.Status, null);
            else
            {
                // Resolve once, then target that specific session to avoid stopping a replacement.
                if (target is null) target = (await Send(MonitorControlKind.Status, null)).SessionId;
                result = await Send(MonitorControlKind.Stop, target);
                if (result.Outcome != MonitorControlOutcome.StopAccepted)
                    return await FailAsync(error, json, DataError, result.Outcome.ToString().ToLowerInvariant(),
                        "Stop was not accepted; check session identity, authorization and lifecycle.");
            }
            string state = result.State switch
            {
                MonitorControlState.Starting => "starting",
                MonitorControlState.Monitoring => "monitoring",
                _ => "stopping"
            };
            var assessment = detailed ? PipelineHealth.Assess(result.Counters, result.SampledUtc, DateTimeOffset.UtcNow,
                result.State == MonitorControlState.Monitoring) : null;
            await WriteAsync(output, json, new { schemaVersion = SchemaVersion, provenance = "same_user_local_endpoint",
                mode = "foreground_headless", sessionId = result.SessionId, state, stopAllowed = result.StopAllowed,
                outcome = stop ? "stop_requested" : "available", result.ObservedUtc, result.SampledUtc, result.Counters, assessment,
                sourceHealth = "not_assessed", detectionValidation = "not_assessed" },
                stop ? $"Stop requested for {result.SessionId:D}; shutdown not confirmed." :
                    $"Foreground monitor: {state} | session {result.SessionId:D} | stop allowed: {result.StopAllowed} | " +
                    (result.Counters is null ? "Counters unavailable." : $"Captured: {result.Counters.Captured}, parsed: {result.Counters.Parsed}, parse errors: {result.Counters.ParseErrors}, detections: {result.Counters.Detections}.") + (assessment is null ? "" : $" Pipeline: {assessment.State}."));
            return detailed && (assessment?.State is "failed" or "unknown") ? DataError : Success;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException && !token.IsCancellationRequested)
        {
            return await FailAsync(error, json, DataError, "monitor_unavailable", stop ? "Foreground IPC endpoint unavailable or invalid; stop outcome not confirmed." :
                    "Foreground IPC endpoint unavailable or invalid.");
        }
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
            $"Saved catalog: {page.Total} rows (offset {page.Offset}, limit {page.Limit})\n" +
            string.Join("\n", page.Rules.Select(r => $"{r.RuleId} {r.Name ?? "(name unavailable)"}")));
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
