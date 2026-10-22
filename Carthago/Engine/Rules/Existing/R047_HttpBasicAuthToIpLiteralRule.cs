// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R047_HttpBasicAuthToIpLiteralRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R047_HttpBasicAuthToIpLiteralRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R047",
            Name: "HTTP Basic Auth to IP Literal",
            Category: "HTTP",
            Description: "HTTP Basic Auth to IP literal",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R047.Enabled",
            EnabledByDefault: true);
    }
}
