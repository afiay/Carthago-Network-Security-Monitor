// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R020_OutboundSmtpDirectToInternetRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R020_OutboundSmtpDirectToInternetRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R020",
            Name: "Outbound SMTP Direct to Internet",
            Category: "Egress",
            Description: "Direct outbound SMTP to internet",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R020.Enabled",
            EnabledByDefault: true);
    }
}
