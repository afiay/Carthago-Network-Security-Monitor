// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/KubernetesContainerPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class KubernetesContainerPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected KubernetesContainerPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
