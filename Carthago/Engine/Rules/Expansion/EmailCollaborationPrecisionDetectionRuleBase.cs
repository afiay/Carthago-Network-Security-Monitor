// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/EmailCollaborationPrecisionDetectionRuleBase.cs
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class EmailCollaborationPrecisionDetectionRuleBase : EvidenceDrivenPrecisionRuleBase
    {
        protected EmailCollaborationPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }
    }
}
