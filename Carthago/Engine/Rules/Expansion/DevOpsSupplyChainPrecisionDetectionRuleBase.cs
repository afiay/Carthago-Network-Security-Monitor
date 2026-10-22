// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/DevOpsSupplyChainPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class DevOpsSupplyChainPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected DevOpsSupplyChainPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
