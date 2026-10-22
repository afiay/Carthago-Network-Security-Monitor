// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R038_EncryptedDnsBootstrapRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R038_EncryptedDnsBootstrapRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R038",
            Name: "Encrypted DNS Bootstrap",
            Category: "DNS",
            Description: "Encrypted DNS bootstrap behavior",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R038.Enabled",
            EnabledByDefault: true);
    }
}
