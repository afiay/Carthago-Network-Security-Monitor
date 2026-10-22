// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/OTIndustrialPackProvider.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal sealed class OTIndustrialPackProvider : CompiledContentPackProviderBase
    {
        private static readonly IReadOnlyList<string> SourceRules = Concat(
            Range(120, 122),
            Range(223, 242),
            Range(473, 492),
            Range(340, 346)).ToArray();

        private readonly ContentPackManifest _manifest = new()
        {
            PackId = "carthago.ot-industrial.v1",
            Name = "OT / Industrial Pack",
            Version = "1.0.0",
            Description = "Optional OT pack for Modbus, BACnet, S7, DNP3, IEC-104, OPC UA, engineering-workstation misuse, and IT/OT boundary violations.",
            Category = "OTIndustrial",
            Author = "Carthago",
            MinimumCarthagoVersion = "1.0.0",
            Rules = AliasRules("OT", SourceRules, "OTIndustrial"),
            Profiles = Profiles(
                Profile("OTSegment", RuleMode.Alert, 0.75, "Alert when OT segments and controllers are explicitly configured.", "Approved.OtSegments"),
                Profile("Enterprise", RuleMode.Shadow, null, "Enterprise defaults shadow OT detections unless OT segments are known."),
                Profile("HomeLab", RuleMode.Disabled, null, "Disabled until OT controllers and segments are explicitly configured.", "Approved.OtSegments"),
                Profile("Research", RuleMode.Alert, 0.60, "Research keeps OT detections broad for replay and validation.", "Approved.OtSegments")
            ),
            RequiredTelemetry = new List<string> { "OT/ICS protocol metadata", "approved OT segments", "engineering workstation inventory" },
            ReplaySamples = Samples(
                Sample("ot-modbus-write", @"Tests/RuleReplaySamples/malicious/modbus-write-function.json", ReplaySampleClassification.Malicious, "Positive sample for Modbus write behavior.", "OT021"),
                Sample("ot-benign-approved-read", @"Tests/RuleReplaySamples/benign/normal-ot-approved-modbus-read.json", ReplaySampleClassification.Benign, "Approved Modbus read traffic should stay non-paging.")
            ),
            Benchmarks = BenchmarkExpectations(
                Benchmark("OTSegment", 0.75, 0),
                Benchmark("Research", 0.80, 1)
            ),
            HuntingQueries = Hunts(
                Hunt("ot-hunt-001", "Modbus writes", "Find Modbus register and coil write behavior.", "OT021", 0.70),
                Hunt("ot-hunt-002", "BACnet writes", "Review BACnet WriteProperty and device-control operations.", "OT033", 0.70),
                Hunt("ot-hunt-003", "OT protocol outside segment", "Find OT protocols crossing unapproved boundaries.", "OT004", 0.70),
                Hunt("ot-hunt-004", "Engineering workstation to internet", "Review OT admin and engineering workstation traffic leaving the segment.", "OT044", 0.65)
            ),
            ResponseRecommendations = Recommendations(
                Recommend("ot-response-001", "Notify OT engineer", "Recommend notifying the OT engineer or control-systems owner for review.", ResponseActionType.MarkForReview, ResponseActionSafety.RecommendationOnly, "Do not auto-block controller traffic. Validate safety impact with OT engineering first.", new[] { "OT021", "OT033", "OT041" }, "Notify the OT duty owner.", "Provide the cited EventId and rule context."),
                Recommend("ot-response-002", "Collect packet evidence bundle", "Recommend preserving packet evidence and controller communication context.", ResponseActionType.ExportEvidenceBundle, ResponseActionSafety.Informational, "Packet collection remains read-only and should precede any control action.", new[] { "OT001", "OT004", "OT021", "OT033" }, "Preserve packets and timing.", "Correlate with historian or PLC operator notes."),
                Recommend("ot-response-003", "Do not auto-block controller traffic", "Explicit reminder that blind network blocking can create operational and safety hazards.", ResponseActionType.MarkForReview, ResponseActionSafety.RecommendationOnly, "Do not auto-block controller or field-device traffic without OT approval.", new[] { "OT001", "OT004", "OT021", "OT033", "OT050" }, "Review safety consequences with OT engineering.", "Prefer observational containment first.")
            ),
            DashboardPresets = Presets(
                Preset("ot-dashboard-001", "OT Boundary & Control Actions", "Highlights boundary violations, control writes, and engineering-workstation misuse.", "OTSegment", ("category", "OTIndustrial")),
                Preset("ot-dashboard-002", "Research OT Validation", "Broad OT replay and tuning preset.", "Research", ("packId", "carthago.ot-industrial.v1"))
            ),
            References = References(
                Ref("MITRE ATT&CK ICS", "ICS technique matrix", "https://attack.mitre.org/matrices/ics/"),
                Ref("CISA", "ICS recommended practices", "https://www.cisa.gov/resources-tools/resources/improving-industrial-control-systems-cybersecurity-defensible-architecture"),
                Ref("Sigma", "Industrial protocol detection guidance", "https://sigmahq.io/docs/")
            ),
            Changelog = new List<string> { "1.0.0 - Initial compiled OT and industrial pack release." },
            SafetyNotes = new List<string>
            {
                "Never auto-block controller or engineering-workstation traffic from this pack.",
                "OT detections stay disabled until approved segments are configured where required."
            },
            License = "MIT"
        };

        public override ContentPackManifest Manifest => _manifest;
    }
}
