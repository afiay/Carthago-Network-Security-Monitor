# Carthago precision-first advanced refactor

This pass continues from the previous precision-profile refactor and adds a second runtime precision layer. The goal is to keep the full 544-rule catalog available while preventing weak non-core expansion rules from paging as high/critical alerts.

## Advanced changes made

### 1. Runtime precision decision layer

Added:

- `Engine/Rules/Abstractions/RulePrecisionRuntimeEvaluator.cs`

This evaluates a candidate detection after the detector has matched but before the event is allowed to emit as an alert. It combines:

- rule precision profile default mode,
- configured runtime mode,
- required telemetry validation,
- required field validation,
- confidence floor,
- observed evidence kinds,
- high/critical evidence-family requirements,
- environment-scoped rule safety.

The evaluator returns `RulePrecisionRuntimeDecision`, including:

- profile mode,
- configured mode,
- effective mode,
- telemetry/evidence/confidence status,
- confidence percent,
- observed evidence families,
- missing telemetry/fields,
- explanatory reasons.

Weak detections are not deleted. They are downgraded to Shadow/Suppressed depending on profile/config, so coverage is preserved but noisy or unsafe alerts do not page.

### 2. Runtime tuning integration

Updated:

- `Engine/RuleEngine.Tuning.cs`

`ResolveRuntimeTuningDecision(...)` now calls `RulePrecisionRuntimeEvaluator.Evaluate(...)` and combines the result with the existing tuning catalog using the most restrictive mode.

This makes precision enforcement active at runtime, not only catalog/documentation-level.

### 3. Stricter telemetry definitions

Updated:

- `Engine/Rules/Abstractions/RulePrecisionProfile.cs`
- `Engine/Rules/Execution/RuleCandidateSelector.cs`
- `Engine/Rules/ExtendedRuleDetectors.cs`

The following are now stricter:

- HTTP requires actual HTTP fields such as method, host, URI, headers, or user-agent.
- TLS requires SNI, TLS version, JA3/JA4, certificate, or other TLS-specific fields.
- DNS requires DNS query/answer metadata.
- Kubernetes requires Kubernetes context, API paths, service-account/container indicators, or API-server port plus contextual fields.
- Directory/AD requires protocol/context evidence, not only LDAP/Kerberos/SMB ports.
- OT/ICS requires protocol/controller context or port plus contextual fields.
- Identity/admin rules require identity/admin text or process/request context, not only common admin ports.

### 4. High/Critical safety gate

For non-core rules, especially R123+:

- one keyword is not enough,
- one host substring is not enough,
- one port is not enough,
- a generic protocol string is not enough,
- high/critical candidates require field-level evidence, aggregation, baseline, entropy, or at least two independent evidence families.

### 5. Regression coverage added to test harness

Updated:

- `Tests/Program.cs`

Added assertions covering:

- TLS rule must not run safely from TCP/443 alone.
- Kubernetes rule must not run safely from TCP/6443 alone.
- weak high-severity text/port candidate is downgraded by runtime precision.
- existing HTTP payload validation remains supported.

## Files changed

- `Engine/Rules/Abstractions/RulePrecisionRuntimeEvaluator.cs`
- `Engine/Rules/Abstractions/RulePrecisionProfile.cs`
- `Engine/Rules/Execution/RuleCandidateSelector.cs`
- `Engine/Rules/ExtendedRuleDetectors.cs`
- `Engine/RuleEngine.Tuning.cs`
- `Tests/Program.cs`

## Validation status

The .NET SDK is not installed in this execution environment, so I could not run:

```bash
dotnet build Carthago.sln
dotnet test Carthago.sln --no-build
```

I did run static file checks for the touched files, including brace/parenthesis balance and manual inspection of the patched C# regions.

## Recommended local verification

Run:

```bash
dotnet build Carthago.sln
dotnet test Carthago.sln --no-build
```

Then run a targeted manual replay:

1. Replay HTTP payload samples for R084-R093.
2. Replay DNS samples for R094-R103 and R178-R197.
3. Replay TLS/SNI/JA3/JA4 samples for R138-R152 and R258-R272.
4. Replay cloud/Kubernetes/DevOps samples with and without the proper telemetry context.
5. Confirm weak records with only `Protocol=TCP`, `DestinationPort=443`, or broad `Info` text do not emit high/critical alerts.
