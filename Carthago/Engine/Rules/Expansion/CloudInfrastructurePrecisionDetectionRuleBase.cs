// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/CloudInfrastructurePrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class CloudInfrastructurePrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected CloudInfrastructurePrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
