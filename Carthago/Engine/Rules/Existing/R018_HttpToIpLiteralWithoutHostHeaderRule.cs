// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R018_HttpToIpLiteralWithoutHostHeaderRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R018_HttpToIpLiteralWithoutHostHeaderRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R018",
            Name: "HTTP to IP Literal Without Host Header",
            Category: "HTTP",
            Description: "HTTP request to IP literal without Host header",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R018.Enabled",
            EnabledByDefault: true);
    }
}
