// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/LegacyDetectionRuleBase.cs
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;

namespace Carthago.Engine.Rules
{
    public abstract class LegacyDetectionRuleBase : DetectionRuleBase
    {
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(RuleEngine.EvaluateExistingRule(Descriptor.RuleId, Descriptor, context));
        }
    }
}
