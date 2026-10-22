// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleTelemetryValidator.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    public sealed record RuleTelemetryValidationResult(
        string RuleId,
        bool FullySupported,
        bool PartiallySupported,
        bool CanRunSafely,
        IReadOnlyList<string> MissingRequiredTelemetry,
        IReadOnlyList<string> MissingOptionalTelemetry,
        IReadOnlyList<string> Warnings);

    public static class RuleTelemetryValidator
    {
        public static RuleTelemetryValidationResult Validate(IDetectionRule rule, TrafficRecord record)
        {
            if (rule == null) throw new ArgumentNullException(nameof(rule));

            var missingRequired = new List<string>();
            var missingOptional = new List<string>();
            var warnings = new List<string>();
            var intelligence = rule.Intelligence;

            foreach (var req in intelligence.TelemetryRequirements)
            {
                var present = HasTelemetry(req.Name, record);
                if (!present && req.Required) missingRequired.Add(req.Name);
                if (!present && !req.Required) missingOptional.Add(req.Name);
            }

            var precision = RulePrecisionCatalog.Validate(rule.Descriptor.RuleId, record);
            missingRequired.AddRange(precision.MissingTelemetry.Select(name => "precision." + name));
            missingRequired.AddRange(precision.MissingFields.Select(name => "field." + name));
            warnings.AddRange(precision.Warnings);

            if (missingRequired.Count > 0)
                warnings.Add($"{rule.Descriptor.RuleId} has missing required telemetry: {string.Join(", ", missingRequired.Distinct(StringComparer.OrdinalIgnoreCase))}");
            if (missingOptional.Count > 0)
                warnings.Add($"{rule.Descriptor.RuleId} has missing optional telemetry: {string.Join(", ", missingOptional.Distinct(StringComparer.OrdinalIgnoreCase))}");

            var required = missingRequired.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
            var optional = missingOptional.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

            return new RuleTelemetryValidationResult(
                RuleId: rule.Descriptor.RuleId,
                FullySupported: required.Length == 0 && optional.Length == 0,
                PartiallySupported: required.Length == 0 && optional.Length > 0,
                CanRunSafely: required.Length == 0,
                MissingRequiredTelemetry: required,
                MissingOptionalTelemetry: optional,
                Warnings: warnings.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        }

        private static bool HasTelemetry(string name, TrafficRecord r)
        {
            if (r == null || string.IsNullOrWhiteSpace(name)) return false;

            return name.ToLowerInvariant() switch
            {
                "source_ip" => !string.IsNullOrWhiteSpace(r.Source),
                "destination_ip_or_host" => RulePrecisionCatalog.HasField("destination_or_host", r),
                "protocol_or_port" => RulePrecisionCatalog.HasField("protocol_or_port", r),
                "mac_address_or_host_identity" => RulePrecisionCatalog.HasField("asset_identity", r),
                "baseline_store" => true,
                "ipv6_or_multicast_fields" => RulePrecisionCatalog.HasField("ipv6_or_multicast", r),
                "remote_service_port_or_protocol" => RulePrecisionCatalog.HasField("identity_context", r),
                "http_payload_or_headers" => RulePrecisionCatalog.HasField("http_any", r) && RulePrecisionCatalog.HasField("payload_or_uri", r),
                "normalized_payload" => RulePrecisionCatalog.HasTelemetryKind(RuleTelemetryKind.NormalizedPayload, r),
                "dns_query_metadata" => RulePrecisionCatalog.HasField("dns_qname", r),
                "upload_direction_and_saas_host" => RulePrecisionCatalog.HasField("http_upload_or_large_flow", r) && RulePrecisionCatalog.HasField("saas_or_cloud_host", r),
                "iot_ot_protocol_context" => RulePrecisionCatalog.HasField("iot_or_ot_context", r),
                "engine_health_snapshot" => RulePrecisionCatalog.HasField("engine_health_signal", r),
                "traffic_record_text_and_protocol_fields" => HasAnyTextOrProtocolField(r),
                "kubernetes_container_indicators" => RulePrecisionCatalog.HasField("kubernetes_context", r),
                "cloud_devops_indicators" => RulePrecisionCatalog.HasField("devops_or_cloud_context", r) || RulePrecisionCatalog.HasField("cloud_context", r),
                "ot_ics_protocol_context" => RulePrecisionCatalog.HasField("iot_or_ot_context", r),
                "platform_health_signal" => RulePrecisionCatalog.HasField("engine_health_signal", r),
                _ => false
            };
        }

        private static bool HasAnyTextOrProtocolField(TrafficRecord r)
        {
            return RulePrecisionCatalog.HasField("protocol_or_port", r)
                   && (!string.IsNullOrWhiteSpace(r.Info)
                       || !string.IsNullOrWhiteSpace(r.HttpUri)
                       || !string.IsNullOrWhiteSpace(r.HttpHost)
                       || !string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                       || !string.IsNullOrWhiteSpace(r.HttpUserAgent)
                       || !string.IsNullOrWhiteSpace(r.Sni)
                       || !string.IsNullOrWhiteSpace(r.DnsQname)
                       || !string.IsNullOrWhiteSpace(r.ProcessName)
                       || !string.IsNullOrWhiteSpace(r.WhoisOrganization)
                       || !string.IsNullOrWhiteSpace(r.WhoisASN));
        }
    }
}
