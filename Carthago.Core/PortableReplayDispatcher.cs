// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules.Expansion;

namespace Carthago.Engine.Rules;

/// <summary>One capture-state epoch; no host dependencies, policy promotion or alert publication.</summary>
internal sealed class PortableReplayDispatcher
{
    private readonly PortableR586Detector _r586 = new();
    private readonly PortableR587Detector _r587 = new();
    private readonly PortableR588Detector _r588 = new();
    private readonly PortableR589Detector _r589 = new();
    private readonly PortableR590Detector _r590 = new();

    internal static bool Supports(string ruleId) => ruleId is "R586" or "R587" or "R588" or "R589" or "R590";

    internal WebSignatureObservation Evaluate(string ruleId, PacketEvaluationContext context, out string method)
    {
        switch (ruleId)
        {
            case "R586": return _r586.Evaluate(context, out method);
            case "R587": return _r587.Evaluate(context, out method);
            case "R588": return _r588.Evaluate(context, out method);
            case "R589": return _r589.Evaluate(context, out method);
            case "R590": return _r590.Evaluate(context, out method);
            default: throw new ArgumentException("Unsupported portable detector.", nameof(ruleId));
        }
    }
}
