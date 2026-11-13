// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules.Expansion;

namespace Carthago.Engine.Rules;

/// <summary>One capture-state epoch; no host dependencies, policy promotion or alert publication.</summary>
internal sealed class PortableReplayDispatcher
{
    private readonly PortableR589Detector _r589 = new();
    private readonly PortableR587Detector _r587 = new();
    internal static bool Supports(string ruleId) => ruleId is "R587" or "R589";

    internal WebSignatureObservation Evaluate(string ruleId, PacketEvaluationContext context, out string method)
    {
        if (!Supports(ruleId)) throw new ArgumentException("Unsupported portable detector.", nameof(ruleId));
        return ruleId == "R587" ? _r587.Evaluate(context, out method) : _r589.Evaluate(context, out method);
    }
}
