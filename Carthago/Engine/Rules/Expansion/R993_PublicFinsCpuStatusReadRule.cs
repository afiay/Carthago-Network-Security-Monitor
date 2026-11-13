// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2760 / AN1900.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R993_PublicFinsCpuStatusReadRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R993", Name: "Public FINS CPU Unit Status Read", Category: "IotOtAdvanced",
            Description: "Exact local CPU FINS/UDP command 0601 without parameters; no returned mode. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R993.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact local CPU FINS/UDP command 0601 without parameters; no returned mode.", "R985 STOP is a different command; R983 TCP negotiation not a status read.");
        public R993_PublicFinsCpuStatusReadRule() : base(Rule, Profile, IndustrialBatchOperation.FinsCpuStatusRead,
            9600, false, true, 12, 12, "R2760") { }
    }
}
