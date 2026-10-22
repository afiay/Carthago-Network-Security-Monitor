// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R040_LongLivedLowThroughputEncryptedSessionRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R040_LongLivedLowThroughputEncryptedSessionRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R040",
            Name: "Long-Lived Low-Throughput Encrypted Session",
            Category: "TLS",
            Description: "Long-lived low-throughput encrypted session",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R040.Enabled",
            EnabledByDefault: true);
    }
}
