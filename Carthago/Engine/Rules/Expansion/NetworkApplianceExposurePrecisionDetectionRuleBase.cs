// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/NetworkApplianceExposurePrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class NetworkApplianceExposurePrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected NetworkApplianceExposurePrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
