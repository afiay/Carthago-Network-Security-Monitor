// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/EvasionTunnelPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class EvasionTunnelPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected EvasionTunnelPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
