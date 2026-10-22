// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/ActiveDirectoryWindowsPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class ActiveDirectoryWindowsPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected ActiveDirectoryWindowsPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
