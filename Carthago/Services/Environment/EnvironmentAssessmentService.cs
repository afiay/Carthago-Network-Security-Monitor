// SPDX-License-Identifier: MIT
// File: Services/Environment/EnvironmentAssessmentService.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Services.EnvironmentTuning
{
    public sealed record EnvironmentAssessment(
        NetworkBoundaryDecision SourceBoundary,
        NetworkBoundaryDecision DestinationBoundary,
        AssetProfile SourceAsset,
        AssetProfile DestinationAsset,
        bool IsBoundaryCrossing,
        bool IsApprovedDestination,
        IReadOnlyList<string> RiskModifiers,
        IReadOnlyList<DetectionEvidenceItem> EvidenceItems)
    {
        public static EnvironmentAssessment Empty { get; } = new(
            new NetworkBoundaryDecision(string.Empty, NetworkBoundaryZone.Unknown, "empty", false, false),
            new NetworkBoundaryDecision(string.Empty, NetworkBoundaryZone.Unknown, "empty", false, false),
            AssetProfile.Unknown(null),
            AssetProfile.Unknown(null),
            false,
            false,
            Array.Empty<string>(),
            Array.Empty<DetectionEvidenceItem>());
    }

    public sealed class EnvironmentAssessmentService
    {
        private static EnvironmentAssessmentService _current = new(NetworkBoundaryProfile.DefaultLocal(), new AssetProfileCatalog());

        private readonly NetworkBoundaryProfile _boundaryProfile;
        private readonly AssetProfileCatalog _assetCatalog;

        public EnvironmentAssessmentService(NetworkBoundaryProfile? boundaryProfile = null, AssetProfileCatalog? assetCatalog = null)
        {
            _boundaryProfile = boundaryProfile ?? NetworkBoundaryProfile.DefaultLocal();
            _assetCatalog = assetCatalog ?? new AssetProfileCatalog();
        }

        public static EnvironmentAssessmentService Current => _current;

        public static EnvironmentAssessmentService FromOptions(EnvironmentTuningOptions? options, ApprovedAssetRegistry? approvedRegistry = null)
        {
            var approved = options?.Approved ?? new ApprovedEnvironmentOptions();
            var external = approved.MqttBrokers
                .Concat(approved.DnsResolvers)
                .Concat(approved.ProxyServers)
                .Concat(approved.VpnGateways)
                .Concat(approved.CloudStorageProviders)
                .Concat(approved.KubernetesApiServers)
                .Concat(approved.CiCdServers)
                .Concat(approved.CameraNvrHosts)
                .Concat(approved.KnownDynamicDnsDomains)
                .Concat(approved.KnownRemoteSupportTools)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var internalApproved = approved.AdminHosts
                .Concat(approved.DomainControllers)
                .Concat(approved.ModbusControllers)
                .Concat(approved.BacnetControllers)
                .Where(static value => !string.IsNullOrWhiteSpace(value))
                .Select(static value => value.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var defaults = NetworkBoundaryProfile.DefaultLocal();
            var internalCidrs = defaults.InternalCidrs
                .Concat(approved.OtSegments.Where(static value => !string.IsNullOrWhiteSpace(value)).Select(static value => value.Trim()))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var boundary = defaults with
            {
                InternalCidrs = internalCidrs,
                ApprovedExternalDestinations = external,
                ApprovedInternalDestinations = internalApproved
            };

            return new EnvironmentAssessmentService(boundary, new AssetProfileCatalog(approvedRegistry ?? ApprovedAssetRegistry.Current));
        }

        public static void Configure(EnvironmentAssessmentService? service)
            => _current = service ?? new EnvironmentAssessmentService(NetworkBoundaryProfile.DefaultLocal(), new AssetProfileCatalog());

        public EnvironmentAssessment Assess(TrafficRecord? record)
        {
            if (record == null)
                return EnvironmentAssessment.Empty;

            var sourceValue = FirstNonEmpty(record.Source, record.MacSource);
            var destinationValue = FirstNonEmpty(record.Destination, record.HttpHost, record.Sni, record.DnsQname, record.MacDestination);
            var sourceBoundary = _boundaryProfile.ClassifyAddress(sourceValue);
            var destinationBoundary = _boundaryProfile.ClassifyAddress(destinationValue);
            var sourceAsset = _assetCatalog.ResolveSource(record);
            var destinationAsset = _assetCatalog.ResolveDestination(record);
            var boundaryCrossing = NetworkBoundaryProfile.IsBoundaryCrossing(sourceBoundary, destinationBoundary);
            var approvedDestination = _boundaryProfile.IsApprovedDestination(destinationValue);
            var modifiers = BuildRiskModifiers(sourceBoundary, destinationBoundary, sourceAsset, destinationAsset, boundaryCrossing, approvedDestination);
            var evidence = BuildEvidence(sourceBoundary, destinationBoundary, sourceAsset, destinationAsset, boundaryCrossing, approvedDestination, modifiers);

            return new EnvironmentAssessment(
                sourceBoundary,
                destinationBoundary,
                sourceAsset,
                destinationAsset,
                boundaryCrossing,
                approvedDestination,
                modifiers,
                evidence);
        }

        private static IReadOnlyList<string> BuildRiskModifiers(
            NetworkBoundaryDecision sourceBoundary,
            NetworkBoundaryDecision destinationBoundary,
            AssetProfile sourceAsset,
            AssetProfile destinationAsset,
            bool boundaryCrossing,
            bool approvedDestination)
        {
            var modifiers = new List<string>();

            if (boundaryCrossing && sourceBoundary.IsInternalLike && destinationBoundary.Zone == NetworkBoundaryZone.External)
                modifiers.Add("internal-to-external");
            if (sourceBoundary.Zone == NetworkBoundaryZone.External && destinationBoundary.IsInternalLike)
                modifiers.Add("external-to-internal");
            if (sourceBoundary.Zone == NetworkBoundaryZone.Management || destinationBoundary.Zone == NetworkBoundaryZone.Management)
                modifiers.Add("management-zone");
            if (sourceAsset.Role is AssetRole.IoTDevice or AssetRole.CameraNvr && destinationBoundary.Zone == NetworkBoundaryZone.External)
                modifiers.Add("iot-egress");
            if (sourceAsset.Role == AssetRole.Workstation && destinationAsset.Role is AssetRole.DatabaseServer or AssetRole.DomainController or AssetRole.KubernetesApiServer)
                modifiers.Add("workstation-to-sensitive-service");
            if (sourceAsset.IsApprovedScanner)
                modifiers.Add("approved-scanner-candidate");
            if (approvedDestination || destinationAsset.IsApprovedService)
                modifiers.Add("approved-destination");

            return modifiers.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }

        private static IReadOnlyList<DetectionEvidenceItem> BuildEvidence(
            NetworkBoundaryDecision sourceBoundary,
            NetworkBoundaryDecision destinationBoundary,
            AssetProfile sourceAsset,
            AssetProfile destinationAsset,
            bool boundaryCrossing,
            bool approvedDestination,
            IReadOnlyList<string> modifiers)
        {
            var items = new List<DetectionEvidenceItem>
            {
                new("source.zone", sourceBoundary.Zone.ToString(), "environment"),
                new("destination.zone", destinationBoundary.Zone.ToString(), "environment"),
                new("source.asset_role", sourceAsset.Role.ToString(), "environment"),
                new("destination.asset_role", destinationAsset.Role.ToString(), "environment"),
                new("boundary.crossing", boundaryCrossing ? "true" : "false", "environment"),
                new("destination.approved", approvedDestination ? "true" : "false", "environment")
            };

            if (!string.IsNullOrWhiteSpace(sourceBoundary.MatchedBy))
                items.Add(new DetectionEvidenceItem("source.zone_match", sourceBoundary.MatchedBy, "environment"));
            if (!string.IsNullOrWhiteSpace(destinationBoundary.MatchedBy))
                items.Add(new DetectionEvidenceItem("destination.zone_match", destinationBoundary.MatchedBy, "environment"));
            if (sourceAsset.Tags.Count > 0)
                items.Add(new DetectionEvidenceItem("source.asset_tags", string.Join(",", sourceAsset.Tags), "environment"));
            if (destinationAsset.Tags.Count > 0)
                items.Add(new DetectionEvidenceItem("destination.asset_tags", string.Join(",", destinationAsset.Tags), "environment"));
            if (modifiers.Count > 0)
                items.Add(new DetectionEvidenceItem("environment.modifiers", string.Join(",", modifiers), "environment"));

            return items;
        }

        private static string? FirstNonEmpty(params string?[] values)
        {
            foreach (var value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                    return value.Trim();
            }

            return null;
        }
    }
}
