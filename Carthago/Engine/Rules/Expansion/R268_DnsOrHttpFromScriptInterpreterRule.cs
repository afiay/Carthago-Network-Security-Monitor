// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R268_DnsOrHttpFromScriptInterpreterRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R268_DnsOrHttpFromScriptInterpreterRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R268",
            Name: "DNS Or HTTP From Script Interpreter",
            Category: "EvasionInfra",
            Description: "Detects dns or http from script interpreter only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R268.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R268",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "The rule must observe concrete telemetry evidence tied to the named behavior.",
                "The event must include a source and either a destination/host, process, protocol, or pipeline component.",
                "Generic descriptor text alone must not produce a match."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 82,
            threshold: 1,
            window: TimeSpan.FromMinutes(20),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Developer workstations, automation runners, and managed scripts can legitimately use interpreters for network access." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R268 evidence-gated sample", "negative R268 descriptor-only sample", "negative R268 missing telemetry sample" });

        public R268_DnsOrHttpFromScriptInterpreterRule() : base(Rule, Profile) { }

        private readonly NetworkBatch266270Evidence.DistinctWindow _observed = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch266270Evidence.InterpreterDnsOrHttp(r, out var kind)) return NoMatch();
            var key = r.Source + "|" + r.ProcessId + "|" + r.Destination + "|" + kind;
            if (_observed.Observe(r, context.TimestampUtc, key, TimeSpan.FromMinutes(20)) == 0) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "exact_interpreter_process,typed_dns_or_cleartext_http", "rule"),
                new("network.observedRequest", kind, "rule")
            };
            evidence.AddRange(AnalystContext("An exact interpreter basename was co-observed with a typed DNS query or parsed cleartext HTTP request.",
                "No command-line execution or script contents were observed, and HTTPS payloads are not decrypted.",
                "Developer workstations and automation agents legitimately use interpreters.",
                "Correlate the PID and request with trusted process-command-line telemetry."));
            return MatchEvasionInfra(context, SeverityLevel.High,
                "Interpreter with typed DNS/cleartext HTTP request (execution unverified)", "ScriptInterpreterEgress",
                evidence, c => { c.AddEvidence(0.34, "typed-request"); c.AddEvidence(0.22, "exact-interpreter"); c.AddEvidence(0.18, "external-destination"); },
                cooldownKey: key + ":interpreter");
        }
    }
}
