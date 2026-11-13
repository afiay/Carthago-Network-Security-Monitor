// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2706 / AN2045.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R990_PublicBacnetInputOutOfServiceRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R990", Name: "Public BACnet input Out_Of_Service true", Category: "IotOtAdvanced",
            Description: "Exact WriteProperty Out_Of_Service (81), Boolean true, Analog Input or Binary Input, no priority/index. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R990.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact WriteProperty Out_Of_Service (81), Boolean true, Analog Input or Binary Input, no priority/index.", "R485 excludes Boolean encoding; R979 changes event notification bits instead. No safety-critical role inferred.");
        public R990_PublicBacnetInputOutOfServiceRule() : base(Rule, Profile, IndustrialBatchOperation.BacnetInputOutOfService,
            47808, false, false, 20, 20, "R2706") { }
    }
}
