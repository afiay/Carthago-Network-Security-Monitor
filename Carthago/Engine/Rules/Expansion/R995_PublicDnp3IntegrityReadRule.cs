// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2690 / AN1920.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R995_PublicDnp3IntegrityReadRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R995", Name: "Public DNP3 four-class integrity read", Category: "IotOtAdvanced",
            Description: "Exact master unconfirmed DNP3 READ, group 60 variations 1–4 once each with qualifier 06, both CRCs valid. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R995.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact master unconfirmed DNP3 READ, group 60 variations 1–4 once each with qualifier 06, both CRCs valid.", "R981 disables unsolicited classes 1–3; this requests static and event data, not returned data.");
        public R995_PublicDnp3IntegrityReadRule() : base(Rule, Profile, IndustrialBatchOperation.Dnp3IntegrityRead,
            20000, false, true, 27, 27, "R2690") { }
    }
}
