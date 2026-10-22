// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/DataLossStagingPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class DataLossStagingPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected DataLossStagingPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
