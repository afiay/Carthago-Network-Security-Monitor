// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/IDetectionRule.cs
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Engine.Rules
{
    public interface IDetectionRule
    {
        RuleDescriptor Descriptor { get; }
        RuleIntelligence Intelligence { get; }

        ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,
            CancellationToken cancellationToken = default);
    }
}
