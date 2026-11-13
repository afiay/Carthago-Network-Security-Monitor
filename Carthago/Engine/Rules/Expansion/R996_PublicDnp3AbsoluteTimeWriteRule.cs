// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2706 / AN2045.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R996_PublicDnp3AbsoluteTimeWriteRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R996", Name: "Public DNP3 absolute time write", Category: "IotOtAdvanced",
            Description: "Exact master DNP3 WRITE, group 50 variation 1, qualifier 07 count 1, one 48-bit absolute time. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R996.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact master DNP3 WRITE, group 50 variation 1, qualifier 07 count 1, one 48-bit absolute time.", "R980 restart and R981 reporting disable are different functions; time value/clock drift not inferred.");
        public R996_PublicDnp3AbsoluteTimeWriteRule() : base(Rule, Profile, IndustrialBatchOperation.Dnp3AbsoluteTimeWrite,
            20000, false, true, 25, 25, "R2706") { }
    }
}
