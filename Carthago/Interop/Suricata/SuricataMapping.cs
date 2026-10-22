// SPDX-License-Identifier: MIT
// File: Interop/Suricata/SuricataMapping.cs
using Carthago.Engine.Rules;

namespace Carthago.Interop.Suricata
{
    public sealed class SuricataRuleReference
    {
        public string RuleId { get; set; } = string.Empty;
        public string Sid { get; set; } = string.Empty;
        public string Note { get; set; } = "Reference only; Carthago behavioral rules are not automatically converted to packet signatures.";
    }

    public static class SuricataMapping
    {
        public static bool IsDirectPacketSignatureCandidate(IDetectionRule rule)
            => rule.Intelligence.SignalKind is RuleSignalKind.Signature or RuleSignalKind.Payload;
    }
}
