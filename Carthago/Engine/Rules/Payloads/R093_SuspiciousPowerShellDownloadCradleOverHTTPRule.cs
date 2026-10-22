// SPDX-License-Identifier: MIT
// File: Engine/Rules/Payloads/R093_SuspiciousPowerShellDownloadCradleOverHTTPRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Payloads
{
    public sealed class R093_SuspiciousPowerShellDownloadCradleOverHTTPRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R093",
            Name: "Suspicious PowerShell Download Cradle over HTTP",
            Category: "Payloads",
            Description: "Concrete telemetry-driven rule for Suspicious PowerShell Download Cradle over HTTP. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R093.Enabled",
            EnabledByDefault: true);
    }
}
