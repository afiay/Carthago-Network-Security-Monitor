// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R013_UncommonPortsServicePortAnomalyRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R013_UncommonPortsServicePortAnomalyRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R013",
            Name: "Uncommon Ports / Service-Port Anomaly",
            Category: "Network",
            Description: "Unexpected service-port pairing",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R013.Enabled",
            EnabledByDefault: true);
    }
}
