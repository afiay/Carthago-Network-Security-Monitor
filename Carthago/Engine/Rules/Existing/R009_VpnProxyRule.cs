// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R009_VpnProxyRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R009_VpnProxyRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R009",
            Name: "VPN / Proxy",
            Category: "Egress",
            Description: "VPN or proxy usage detected",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R009.Enabled",
            EnabledByDefault: true);
    }
}
