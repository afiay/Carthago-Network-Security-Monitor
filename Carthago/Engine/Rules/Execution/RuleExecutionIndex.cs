// SPDX-License-Identifier: MIT
// File: Engine/Rules/Execution/RuleExecutionIndex.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;

namespace Carthago.Engine.Rules.Execution
{
    public sealed record RuleExecutionIndexEntry(
        string RuleId,
        bool AlwaysRun,
        bool RequiresHttp,
        bool RequiresDns,
        bool RequiresTls,
        bool RequiresIoTOrOt,
        bool RequiresIdentityOrAdmin,
        bool RequiresContainerOrCloud,
        IReadOnlyList<string> RequiredTelemetry,
        string Category);

    public sealed class RuleExecutionIndex
    {
        public RuleExecutionIndex(IReadOnlyDictionary<string, RuleExecutionIndexEntry> entries)
            => Entries = entries;

        public IReadOnlyDictionary<string, RuleExecutionIndexEntry> Entries { get; }

        public static RuleExecutionIndex CreateDefault()
        {
            var entries = RuleCatalog.Rules.ToDictionary(
                rule => rule.Descriptor.RuleId,
                rule => BuildEntry(rule),
                StringComparer.OrdinalIgnoreCase);
            return new RuleExecutionIndex(entries);
        }

        private static RuleExecutionIndexEntry BuildEntry(IDetectionRule rule)
        {
            var n = RuleTuningClassifier.RuleNumber(rule.Descriptor.RuleId);
            var profile = RulePrecisionCatalog.GetProfile(rule.Descriptor);
            var requiredTelemetry = rule.Intelligence.TelemetryRequirements
                .Where(static requirement => requirement.Required)
                .Select(static requirement => requirement.Name)
                .Concat(profile.RequiredTelemetry.Select(static kind => "precision." + kind))
                .Concat(profile.RequiredFields.Select(static field => "field." + field))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            var requiresHttp = profile.RequiredTelemetry.Contains(RuleTelemetryKind.Http);
            var requiresDns = profile.RequiredTelemetry.Contains(RuleTelemetryKind.Dns);
            var requiresTls = profile.RequiredTelemetry.Contains(RuleTelemetryKind.Tls)
                              || profile.RequiredTelemetry.Contains(RuleTelemetryKind.Ja3)
                              || profile.RequiredTelemetry.Contains(RuleTelemetryKind.Ja4)
                              || profile.RequiredTelemetry.Contains(RuleTelemetryKind.Sni);
            var requiresOt = profile.RequiredTelemetry.Contains(RuleTelemetryKind.OtIcsProtocol);
            var requiresIdentity = profile.RequiredTelemetry.Contains(RuleTelemetryKind.Identity)
                                   || profile.RequiredTelemetry.Contains(RuleTelemetryKind.Authentication)
                                   || profile.RequiredTelemetry.Contains(RuleTelemetryKind.Directory)
                                   || profile.RequiredTelemetry.Contains(RuleTelemetryKind.Microsoft365Audit);
            var requiresCloud = profile.RequiredTelemetry.Contains(RuleTelemetryKind.CloudAudit)
                                || profile.RequiredTelemetry.Contains(RuleTelemetryKind.KubernetesAudit)
                                || profile.RequiredTelemetry.Contains(RuleTelemetryKind.DevOpsAudit);

            return new RuleExecutionIndexEntry(
                RuleId: rule.Descriptor.RuleId,
                AlwaysRun: n is >= 1 and <= 49 || n is >= 50 and <= 56,
                RequiresHttp: requiresHttp || n is >= 84 and <= 93 || n is >= 104 and <= 112 || n is >= 153 and <= 177 || n is >= 198 and <= 222 || n is >= 273 and <= 332 || n is >= 353 and <= 392 || n is >= 493 and <= 512,
                RequiresDns: requiresDns || n is >= 94 and <= 103 || n is >= 178 and <= 197,
                RequiresTls: requiresTls || n is >= 138 and <= 152 || n is >= 258 and <= 272 || n is >= 513 and <= 528,
                RequiresIoTOrOt: requiresOt || n is >= 113 and <= 122 || n is >= 223 and <= 242 || n is >= 473 and <= 492,
                RequiresIdentityOrAdmin: requiresIdentity || n is >= 73 and <= 83 || n is >= 123 and <= 137 || n is >= 273 and <= 292 || n is >= 333 and <= 352,
                RequiresContainerOrCloud: requiresCloud || n is >= 198 and <= 222 || n is >= 293 and <= 392,
                RequiredTelemetry: requiredTelemetry,
                Category: rule.Descriptor.Category);
        }
    }
}
