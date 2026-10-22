// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/OtIcsDeepPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class OtIcsDeepPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected OtIcsDeepPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
