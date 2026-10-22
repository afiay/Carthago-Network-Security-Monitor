// SPDX-License-Identifier: MIT
// File: Engine/Rules/LateralMovement/R079_LDAPEnumerationSpikeRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R079_LDAPEnumerationSpikeRule : TelemetryDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R079",
            Name: "LDAP Enumeration Spike",
            Category: "LateralMovement",
            Description: "Concrete telemetry-driven rule for LDAP Enumeration Spike. Uses existing TrafficRecord fields and returns NoMatch when required telemetry is absent; it never emits synthetic demo detections.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R079.Enabled",
            EnabledByDefault: true);
    }
}
