// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2706 / AN2045.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R992_PublicBacnetAtomicFileWriteRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R992", Name: "Public BACnet AtomicWriteFile 256-byte stream request", Category: "IotOtAdvanced",
            Description: "Exact File object AtomicWriteFile stream offset zero, canonical 256-byte octet-string payload; no content classification. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R992.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact File object AtomicWriteFile stream offset zero, canonical 256-byte octet-string payload; no content classification.", "R991 read and R485 property write are different services; no firmware or authorization claim.");
        public R992_PublicBacnetAtomicFileWriteRule() : base(Rule, Profile, IndustrialBatchOperation.BacnetAtomicFileWrite,
            47808, false, false, 279, 279, "R2706") { }
    }
}
