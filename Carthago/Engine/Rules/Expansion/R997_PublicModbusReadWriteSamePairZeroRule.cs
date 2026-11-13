// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2714 / AN1908.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R997_PublicModbusReadWriteSamePairZeroRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R997", Name: "Public Modbus FC23 same-pair zero write/read", Category: "IotOtAdvanced",
            Description: "Exact FC23 read/write same two consecutive holding registers, two zero write words, full first client payload, verified TCP handshake. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R997.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact FC23 read/write same two consecutive holding registers, two zero write words, full first client payload, verified TCP handshake.", "R968 single-register burst and R982 mask write use different function codes; no successful write/read inferred.");
        public R997_PublicModbusReadWriteSamePairZeroRule() : base(Rule, Profile, IndustrialBatchOperation.ModbusReadWriteSamePairZero,
            502, true, false, 21, 21, "R2714") { }
    }
}
