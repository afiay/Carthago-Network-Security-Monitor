// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R035_RareSshClientFingerprintRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R035_RareSshClientFingerprintRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R035",
            Name: "Rare SSH Client Fingerprint",
            Category: "SSH",
            Description: "Rare SSH client fingerprint",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R035.Enabled",
            EnabledByDefault: true);
    }
}
