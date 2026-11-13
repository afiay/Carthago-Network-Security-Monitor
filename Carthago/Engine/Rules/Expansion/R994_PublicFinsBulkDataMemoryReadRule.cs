// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2797 / AN2244.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R994_PublicFinsBulkDataMemoryReadRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R994", Name: "Public FINS 256-word Data Memory read", Category: "IotOtAdvanced",
            Description: "Exact FINS Memory Area Read 0101, DM word area 82, 256 words, start 0–32512, bit offset zero. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R994.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact FINS Memory Area Read 0101, DM word area 82, 256 words, start 0–32512, bit offset zero.", "R984 writes 16 words; R994 requests data, not a returned program or configuration.");
        public R994_PublicFinsBulkDataMemoryReadRule() : base(Rule, Profile, IndustrialBatchOperation.FinsBulkDataMemoryRead,
            9600, false, true, 18, 18, "R2797") { }
    }
}
