// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R046_UnauthorizedVpnProtocolEgressRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R046_UnauthorizedVpnProtocolEgressRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R046",
            Name: "Unauthorized VPN Protocol Egress",
            Category: "Egress",
            Description: "Unauthorized VPN protocol egress",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R046.Enabled",
            EnabledByDefault: true);
    }
}
