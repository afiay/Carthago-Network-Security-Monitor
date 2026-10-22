// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/TelemetryDetectionRuleBase.cs
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Engine.Rules
{
    /// <summary>
    /// Base class for concrete R057+ telemetry-driven rules.
    /// The rule class owns the descriptor; the shared detector library owns reusable stateful heuristics.
    /// </summary>
    public abstract class TelemetryDetectionRuleBase : DetectionRuleBase
    {
        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(ExtendedRuleDetectors.Evaluate(Descriptor, context));
        }
    }
}
