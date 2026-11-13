// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2709 / AN2053.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R1000_PublicSnmpIpv4ForwardingDisableRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R1000", Name: "Public SNMP ipForwarding not-forwarding SET", Category: "IotOtAdvanced",
            Description: "Exact SNMPv1/v2c SET single ipForwarding.0 Integer32 not-forwarding(2), zero error/index. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R1000.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact SNMPv1/v2c SET single ipForwarding.0 Integer32 not-forwarding(2), zero error/index.", "R999 addresses one interface; R1000 requests IPv4 forwarding behavior. No actual routing loss inferred.");
        public R1000_PublicSnmpIpv4ForwardingDisableRule() : base(Rule, Profile, IndustrialBatchOperation.SnmpIpv4ForwardingDisable,
            161, false, false, 20, 4096, "R2709") { }
    }
}
