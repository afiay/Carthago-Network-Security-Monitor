# Adding Detection Rules to Carthago

Carthago rules are explicit, durable, and auditable. A rule match must become a `DetectionEvent`, and emitted events must be written to the mandatory local JSONL journal before UI, incident grouping, statistics, exports, or external sinks receive them.

## 1. Choose a RuleId

Use the next unused sequential ID, for example `R123`. Never reuse, rename, or merge existing IDs. Rules `R001` through `R049` are preserved legacy detections. `R050` through `R056` are engine-health detections. `R057` through `R544` are concrete telemetry-driven rules backed by fields already present in `TrafficRecord`.

## 2. Create one file per rule

Create a file under the correct category folder:

```text
Engine/Rules/Custom/R123_CustomRuleNameRule.cs
```

One file must contain one rule class only.

## 3. Implement the rule class

```csharp
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Engine.Rules.Custom
{
    public sealed class R123_CustomRuleNameRule : DetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R123",
            Name: "Custom Rule Name",
            Category: "Custom",
            Description: "Explain the detection and its evidence.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R123.Enabled",
            EnabledByDefault: false);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var record = context.Record;

            if (!/* condition */ false)
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));

            var evt = new DetectionEvent
            {
                RuleId = Descriptor.RuleId,
                RuleName = Descriptor.Name,
                TimestampUtc = context.TimestampUtc,
                Severity = Descriptor.DefaultSeverity,
                SourceIp = record.Source,
                SourcePort = record.SourcePort,
                DestinationIp = record.Destination,
                DestinationPort = record.DestinationPort,
                Protocol = record.Protocol,
                Summary = "Short analyst-friendly summary",
                Evidence = record.Info
            };

            return ValueTask.FromResult(RuleEvaluationResult.Match(Descriptor.RuleId, evt));
        }
    }
}
```

## 4. Access packet and flow context

Use `RuleEvaluationContext.Record` for current traffic data, `context.Sensitivity` for sensitivity scaling, `context.TimestampUtc` for canonical UTC time, and `context.HealthSnapshot` for engine-health telemetry.

## 5. Suppression

Suppression must not mean loss. If your rule intentionally suppresses a repeated match, return `RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId)` so metrics and traces record it as suppressed, not lost.

## 6. Configuration

Add a config entry under the `Rules` profile when the structured rule-config model is extended. For legacy compatibility, rules `R001` through `R049` still map to the existing flat `Enable...` toggles. Keep detection-rule config separate from UI preferences and dashboard layout.

## 7. Register explicitly

Security-sensitive detections are registered explicitly. Add the rule to `Engine/Rules/Catalog/RuleRegistry.cs` and ensure `RuleCatalog.Validate()` returns no errors.

## 8. Add tests

Add tests that prove:

- the new rule has a unique `RuleId`
- the descriptor has a unique `ConfigKey`
- the rule emits `DetectionEvent` only when evidence is present
- disabled rules are skipped, not lost
- journal persistence can read the emitted event back

## 9. Verify durability

Run:

```powershell
dotnet run --project Tests/Carthago.RuleArchitecture.Tests.csproj
```

Then verify that emitted detections are written to:

```text
%ProgramData%\Carthago\detections\detections-YYYY-MM-DD.jsonl
```

## 10. Do not fake missing telemetry

If the required packet, flow, identity, DNS, TLS, process, asset, cloud, or OT telemetry is unavailable, implement the rule so it returns `RuleEvaluationResult.NoMatch(...)` until observable input exists. Do not emit demo-only or fake detections from production rules.

## 11. Safe v2 rule configuration shape

The loader supports the existing flat `rules.json` keys and this safer v2 shape. Prefer the v2 shape for new rules because it keeps rule configuration separate from dashboard/UI preferences and makes rule IDs explicit.

```json
{
  "Version": 2,
  "Profile": "Balanced",
  "Global": {
    "AlertCooldownSeconds": 60
  },
  "Rules": {
    "R001": {
      "Enabled": true,
      "Threshold": 8,
      "WindowSeconds": 30
    },
    "R050": {
      "Enabled": true,
      "WindowSeconds": 10
    },
    "R123": {
      "Enabled": false
    }
  }
}
```

Config reload is defensive: malformed JSON does not replace the active configuration, and the engine records a config reload failure so `R054` can surface it. Unknown fields are preserved during deserialization through extension data and should not be removed by rule code.

## 12. Durability checklist before merging a rule

Before merging a new rule, verify this sequence:

```text
rule match
  -> RuleEvaluationResult.Match(...)
  -> DetectionEvent prepared by RuleEngine
  -> JSONL journal append succeeds
  -> UI / incident correlation / statistics / sinks receive the already-journaled event
```

Never emit directly to UI, incidents, or external sinks from a rule. The rule returns evidence; the engine owns persistence and delivery order.


## Rule-specific tuning fields

For simple numeric tuning, prefer the common v2 rule config fields:

```json
{
  "Rules": {
    "R123": {
      "Enabled": true,
      "Threshold": 10,
      "WindowSeconds": 60,
      "EntropyThreshold": 3.8,
      "AllowedDestinations": ["10.0.0.10", "10.0.0.11"]
    }
  }
}
```

Inside a rule implementation, read those settings with the safe typed helpers:

```csharp
var threshold = RuleEngine.GetRuleIntSetting(Descriptor.RuleId, "Threshold", 10, min: 1, max: 10_000);
var windowSeconds = RuleEngine.GetRuleIntSetting(Descriptor.RuleId, "WindowSeconds", 60, min: 1, max: 86_400);
var entropy = RuleEngine.GetRuleDoubleSetting(Descriptor.RuleId, "EntropyThreshold", 3.8, min: 1.0, max: 8.0);
var allowed = RuleEngine.GetRuleStringListSetting(Descriptor.RuleId, "AllowedDestinations");
```

Unknown config fields are preserved in `JsonExtensionData` instead of being discarded. If a config reload fails, the previous active config remains in use and R054 can report the reload failure.

## External sink failure outbox

Never write a rule directly to Elastic, Splunk, a webhook, syslog, Kafka, or another sink. Emit a `DetectionEvent`; the engine writes it to the mandatory local journal first. If a sink fails later, `DetectionOutbox` writes an append-only JSONL spool entry so the failure is auditable and retryable without losing the local detection.
