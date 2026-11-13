// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules.Expansion;

namespace Carthago.Engine.Rules;

/// <summary>One capture-state epoch; no host dependencies, policy promotion or alert publication.</summary>
internal sealed class PortableReplayDispatcher
{
    private readonly Dictionary<string,PortableRuleCatalog.Evaluator> _evaluators =
        PortableRuleCatalog.CreateEvaluators();

    internal static bool Supports(string ruleId) => PortableRuleCatalog.Find(ruleId) is not null;

    internal WebSignatureObservation Evaluate(string ruleId, PacketEvaluationContext context, out string method)
    {
        if (!_evaluators.TryGetValue(ruleId,out var evaluate))
            throw new ArgumentException("Unsupported portable detector.", nameof(ruleId));
        return evaluate(context,out method);
    }
}
