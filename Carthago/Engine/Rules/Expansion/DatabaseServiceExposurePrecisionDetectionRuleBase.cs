// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/DatabaseServiceExposurePrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class DatabaseServiceExposurePrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected DatabaseServiceExposurePrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
