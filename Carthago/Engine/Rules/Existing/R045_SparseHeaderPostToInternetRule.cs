// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R045_SparseHeaderPostToInternetRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R045_SparseHeaderPostToInternetRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R045",
            Name: "Sparse-Header POST to Internet",
            Category: "HTTP",
            Description: "Sparse-header POST to internet",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R045.Enabled",
            EnabledByDefault: true);
    }
}
