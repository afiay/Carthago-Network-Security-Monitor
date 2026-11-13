// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2797 / AN2244.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R991_PublicBacnetAtomicFileReadRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R991", Name: "Public BACnet AtomicReadFile 512-byte stream request", Category: "IotOtAdvanced",
            Description: "Exact File object AtomicReadFile stream offset zero, requested count 512 bytes; no returned content. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R991.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact File object AtomicReadFile stream offset zero, requested count 512 bytes; no returned content.", "R978 Modbus file response is a different protocol and outcome; this is a request only.");
        public R991_PublicBacnetAtomicFileReadRule() : base(Rule, Profile, IndustrialBatchOperation.BacnetAtomicFileRead,
            47808, false, false, 22, 22, "R2797") { }
    }
}
