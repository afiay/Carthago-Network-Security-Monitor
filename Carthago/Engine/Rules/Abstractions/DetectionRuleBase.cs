// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/DetectionRuleBase.cs
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Engine.Rules
{
    public abstract class DetectionRuleBase : IDetectionRule
    {
        public abstract RuleDescriptor Descriptor { get; }

        public virtual RuleIntelligence Intelligence => RuleIntelligenceFactory.CreateDefault(Descriptor);

        public abstract ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,
            CancellationToken cancellationToken = default);
    }
}
