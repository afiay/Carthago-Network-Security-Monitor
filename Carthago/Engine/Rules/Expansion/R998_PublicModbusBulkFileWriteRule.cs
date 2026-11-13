// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Workbook R2706 / AN2045.
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R998_PublicModbusBulkFileWriteRule : IndustrialBatchPrecisionRule
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R998", Name: "Public Modbus FC21 bulk file-record write", Category: "IotOtAdvanced",
            Description: "Exact FC21 one reference-6 file-record subrequest, 100–120 registers, bounded record range and exact byte counts, verified TCP handshake. Public-to-private request only; authorization, acceptance and effect unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R998.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = BatchProfile(Rule,
            "Exact FC21 one reference-6 file-record subrequest, 100–120 registers, bounded record range and exact byte counts, verified TCP handshake.", "R978 FC20 file read is separate; no file content, firmware or accepted write inferred.");
        public R998_PublicModbusBulkFileWriteRule() : base(Rule, Profile, IndustrialBatchOperation.ModbusBulkFileWrite,
            502, true, false, 216, 256, "R2706") { }
    }
}
