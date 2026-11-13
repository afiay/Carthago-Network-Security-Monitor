// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2690 / AN1920.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R989_PublicBacnetDeviceAllPropertiesReadRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R989", Name: "Public BACnet Device all-properties read", Category: "IotOtAdvanced",
            Description: "Exact Device ReadPropertyMultiple, one device and property ALL (8), no index or additional selectors. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R989.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact Device ReadPropertyMultiple, one device and property ALL (8), no index or additional selectors.", "R977 Object_List reads a directory; this asks for device properties, not completed tag enumeration.");
        public R989_PublicBacnetDeviceAllPropertiesReadRule() : base(Rule, Profile, IndustrialBatchOperation.BacnetDeviceAllPropertiesRead,
            47808, false, false, 19, 19, "R2690") { }
    }
}
