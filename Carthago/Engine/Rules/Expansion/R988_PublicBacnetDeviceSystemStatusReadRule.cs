// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2760 / AN1900.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R988_PublicBacnetDeviceSystemStatusReadRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R988", Name: "Public BACnet Device System_Status read", Category: "IotOtAdvanced",
            Description: "Exact Device ReadProperty System_Status (112), no array index; no returned operating mode. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R988.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact Device ReadProperty System_Status (112), no array index; no returned operating mode.", "R977 Object_List is a different property; no status response inferred.");
        public R988_PublicBacnetDeviceSystemStatusReadRule() : base(Rule, Profile, IndustrialBatchOperation.BacnetDeviceSystemStatusRead,
            47808, false, false, 17, 17, "R2760") { }
    }
}
