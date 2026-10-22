// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/IdentityAdvancedPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class IdentityAdvancedPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected IdentityAdvancedPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
