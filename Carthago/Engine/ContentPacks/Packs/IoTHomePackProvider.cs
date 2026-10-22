// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/IoTHomePackProvider.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Benchmarking;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal sealed class IoTHomePackProvider : CompiledContentPackProviderBase
    {
        private static readonly IReadOnlyList<string> SourceRules = Concat(
            Range(113, 119),
            Range(229, 239),
            Range(451, 472)).ToArray();

        private readonly ContentPackManifest _manifest = new()
        {
            PackId = "carthago.iot-home.v1",
            Name = "IoT Home / Small Office Pack",
            Version = "1.0.0",
            Description = "Optional IoT pack for cameras, printers, MQTT, UPnP, discovery storms, default-credential attempts, and unauthorized external control.",
            Category = "IoTHomeSmallOffice",
            Author = "Carthago",
            MinimumCarthagoVersion = "1.0.0",
            Rules = AliasRules("IOT", SourceRules, "IoTHomeSmallOffice"),
            Profiles = Profiles(
                Profile("IoTHeavy", RuleMode.Alert, 0.70, "IoT-heavy sites can alert on clearer device and broker misuse.", "Approved.MqttBrokers"),
                Profile("HomeLab", RuleMode.Shadow, null, "Home labs keep obvious risks visible without paging by default."),
                Profile("SmallBusiness", RuleMode.Shadow, null, "Small offices keep IoT anomalies visible but non-paging until approved assets are defined."),
                Profile("Research", RuleMode.Alert, 0.60, "Research alerts broadly for replay and tuning.")
            ),
            RequiredTelemetry = new List<string> { "MQTT and IoT protocol metadata", "camera and printer inventory", "local discovery visibility" },
            ReplaySamples = Samples(
                Sample("iot-default-credential", @"Tests/RuleReplaySamples/malicious/iot-default-credential-attempt.json", ReplaySampleClassification.Malicious, "Positive sample for default credential attempt against IoT admin services.", "IOT006"),
                Sample("iot-approved-mqtt", @"Tests/RuleReplaySamples/benign/normal-mqtt-approved-broker.json", ReplaySampleClassification.Benign, "Approved MQTT broker activity should stay non-paging.")
            ),
            Benchmarks = BenchmarkExpectations(
                Benchmark("IoTHeavy", 0.70, 0),
                Benchmark("Research", 0.80, 1)
            ),
            HuntingQueries = Hunts(
                Hunt("iot-hunt-001", "Camera and NVR beaconing", "Review unexpected camera or NVR internet beaconing.", "IOT007", 0.60),
                Hunt("iot-hunt-002", "Printer admin exposure", "Find printer and JetDirect admin exposure or external access.", "IOT025", 0.60),
                Hunt("iot-hunt-003", "MQTT topic abuse", "Find topic enumeration and retained-topic misuse.", "IOT002", 0.65),
                Hunt("iot-hunt-004", "Local discovery storms", "Review mDNS, UPnP, and SSDP discovery storms.", "IOT021", 0.55)
            ),
            ResponseRecommendations = Recommendations(
                Recommend("iot-response-001", "Review device ownership", "Recommend validating whether the observed IoT device and destination are expected.", ResponseActionType.MarkForReview, ResponseActionSafety.RecommendationOnly, "Do not auto-block consumer-device traffic from content-pack defaults.", new[] { "IOT007", "IOT033", "IOT040" }, "Identify the physical device.", "Confirm whether the cloud endpoint is approved."),
                Recommend("iot-response-002", "Change default credential recommendation", "Recommend changing default credentials after explicit device-owner approval.", ResponseActionType.MarkForReview, ResponseActionSafety.ApprovalRequired, "Credential changes require owner coordination because many IoT devices are fragile.", new[] { "IOT005", "IOT006" }, "Confirm the device model and credential path.", "Coordinate with the device owner before changing credentials."),
                Recommend("iot-response-003", "Collect packet evidence", "Recommend preserving packet evidence before making any network block decisions.", ResponseActionType.ExportEvidenceBundle, ResponseActionSafety.Informational, "Evidence collection stays read-only by default.", new[] { "IOT001", "IOT021", "IOT032" }, "Preserve packet captures.", "Correlate with the detection journal.")
            ),
            DashboardPresets = Presets(
                Preset("iot-dashboard-001", "Device Beaconing & Discovery", "Focuses on IoT cloud beaconing, discovery storms, and admin exposure.", "IoTHeavy", ("category", "IoTHomeSmallOffice")),
                Preset("iot-dashboard-002", "Research IoT Validation", "Broad device-focused tuning and replay preset.", "Research", ("packId", "carthago.iot-home.v1"))
            ),
            References = References(
                Ref("MITRE ATT&CK", "Discovery", "https://attack.mitre.org/tactics/TA0007/"),
                Ref("CISA", "Securing small and home office devices", "https://www.cisa.gov/resources-tools/resources/securing-small-and-home-office-networks"),
                Ref("Sigma", "IoT and discovery detection guidance", "https://sigmahq.io/docs/")
            ),
            Changelog = new List<string> { "1.0.0 - Initial compiled IoT home and small-office pack release." },
            SafetyNotes = new List<string>
            {
                "Pack never auto-blocks fragile or consumer-grade device traffic.",
                "Evidence collection and owner validation come before any remediation."
            },
            License = "MIT"
        };

        public override ContentPackManifest Manifest => _manifest;
    }
}
