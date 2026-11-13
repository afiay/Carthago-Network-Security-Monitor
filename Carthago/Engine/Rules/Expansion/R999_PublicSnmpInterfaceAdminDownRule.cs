// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2709 / AN2053.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R999_PublicSnmpInterfaceAdminDownRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R999", Name: "Public SNMP ifAdminStatus down SET", Category: "IotOtAdvanced",
            Description: "Exact SNMPv1/v2c SET single ifAdminStatus.<positive canonical ifIndex> Integer32 down(2), zero error/index. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R999.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact SNMPv1/v2c SET single ifAdminStatus.<positive canonical ifIndex> Integer32 down(2), zero error/index.", "R966 enterprise SET and R969 UPS reboot use disjoint OIDs; no interface state or blocked traffic inferred.");
        public R999_PublicSnmpInterfaceAdminDownRule() : base(Rule, Profile, IndustrialBatchOperation.SnmpInterfaceAdminDown,
            161, false, false, 20, 4096, "R2709") { }
    }
}
