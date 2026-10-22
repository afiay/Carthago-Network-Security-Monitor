// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R026_SmbRpcToInternetRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R026_SmbRpcToInternetRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R026",
            Name: "SMB / RPC to Internet",
            Category: "Egress",
            Description: "SMB or RPC to internet",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R026.Enabled",
            EnabledByDefault: true);
    }
}
