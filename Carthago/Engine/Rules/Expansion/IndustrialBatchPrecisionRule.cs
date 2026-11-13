// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Shared capture-only guard for R988–R1000.
using System;
using Carthago.Models;
using Carthago.Services.ProtocolIntelligence;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class IndustrialBatchPrecisionRule : EvidenceDrivenPrecisionRuleBase
    {
        private readonly IndustrialBatchOperation _operation;
        private readonly int _port, _minimumLength, _maximumLength;
        private readonly bool _tcp, _sameSourcePort;
        private readonly string _workbook;
        private readonly WebSignatureCooldown _cooldown = new();

        protected IndustrialBatchPrecisionRule(RuleDescriptor descriptor, RulePrecisionProfile profile,
            IndustrialBatchOperation operation, int port, bool tcp, bool sameSourcePort,
            int minimumLength, int maximumLength, string workbook) : base(descriptor, profile)
        {
            _operation = operation; _port = port; _tcp = tcp; _sameSourcePort = sameSourcePort;
            _minimumLength = minimumLength; _maximumLength = maximumLength; _workbook = workbook;
        }

        protected static RulePrecisionProfile BatchProfile(RuleDescriptor descriptor, string positive, string limitation)
            => CreateEvidenceDrivenProfile(new PrecisionRuleSpec
            {
                RuleId = descriptor.RuleId, Name = descriptor.Name, Category = descriptor.Category,
                Description = descriptor.Description, Severity = descriptor.DefaultSeverity,
                Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
                RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
                RequiredFields = new[] { "source", "destination", "protocol_or_port", "capture_only_industrial_batch_operation" },
                EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
                PositiveConditions = new[] { positive, "Public IPv4 source to private IPv4 destination; complete capture-only classification." },
                NegativeConditions = new[] { "Malformed, truncated, coalesced, other operation, wrong transport or peer, fabricated label, conflicting typed evidence or repeated/reversed event fails closed." },
                FalsePositives = new[] { "Approved engineering, monitoring, initialization and maintenance may produce the same request. " + limitation },
                MinimumConfidence = 80, WindowThreshold = 1, Window = TimeSpan.FromSeconds(60),
                Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "source_destination_operation",
                TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
                RequiredTests = new[] { "two raw capture positives", "operation-specific semantic and framing negatives",
                    "scope, transport, incomplete capture, forgery, contradictory evidence", "cross-rule nonconvergence",
                    "duplicate/reverse time, cooldown, peer isolation, privacy and registry" }
            });

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!(_tcp ? Research786NetworkEvidence.TcpData(r) : Research786NetworkEvidence.UdpData(r)) ||
                !Research786NetworkEvidence.PublicPrivate(r) ||
                r.DestinationPort != _port ||
                (_sameSourcePort ? r.SourcePort != _port :
                    (_tcp || _port == 161) && r.SourcePort == _port) ||
                r.L4Len is not int length || length < _minimumLength || length > _maximumLength ||
                r.IndustrialOperation != _operation ||
                r.ApplicationProtocol != IndustrialBatchInspector.Label(_operation) ||
                r.DnsQname != null || r.DnsIsResponse || r.HttpUri != null || r.HttpMethod != null ||
                r.TlsVersion != null || r.Sni != null || r.LdapCleartextSimpleBindObserved ||
                r.RedisRespConfigSetRequestObserved || r.Smb2CompleteWriteRequestObserved ||
                r.BacnetWritePropertyRequestObserved || r.BacnetDeviceCommunicationDisableObserved ||
                r.BacnetReinitializeDeviceRequestObserved || r.BacnetObjectListReadObserved ||
                r.BacnetEventDisableRequestObserved || r.FinsNodeNegotiationObserved ||
                r.FinsDataMemoryClearObserved || r.FinsControllerStopObserved ||
                r.Dnp3UnsolicitedBinaryEventObserved || r.Dnp3RestartRequestObserved ||
                r.Dnp3DisableUnsolicitedObserved || r.ModbusSingleRegisterWritePoint.HasValue ||
                r.ModbusClearMaskWriteObserved || r.ModbusOversizedReadExceptionObserved ||
                r.ModbusBulkFileReadResponseObserved || r.SnmpEnterpriseSetRequestObserved ||
                r.SnmpUpsRebootRequestObserved || r.SnmpHighDemandGetBulkObserved ||
                r.SnmpSystemFingerprintGetObserved || r.SnmpConnectionTableGetNextObserved ||
                r.Iec104StartupOffExecuteObserved || r.OpcUaHelloAckObserved ||
                r.EtherNetIpRegisterSessionObserved || r.EtherNetIpIdentityResetObserved) return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook." + _workbook, "owner-research"),
                new DetectionEvidenceItem("matched_conditions", IndustrialBatchInspector.Label(_operation)!, "capture"),
                new DetectionEvidenceItem("outcome", "request_only_approval_acceptance_and_operational_effect_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, Descriptor.DefaultSeverity,
                Descriptor.Name + " observed; authorization, acceptance and operational effect unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.55, "complete_native_request_capture");
                    confidence.AddEvidence(0.35, "public_to_private_boundary");
                }, count: 1, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
