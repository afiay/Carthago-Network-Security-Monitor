// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/LocalDiscoveryWirelessPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class LocalDiscoveryWirelessPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected LocalDiscoveryWirelessPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
