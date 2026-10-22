// SPDX-License-Identifier: MIT
// File: Engine/Rules/Existing/R025_TlsCertificateExpiredOrExpiringSoonRule.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules.Existing
{
    public sealed class R025_TlsCertificateExpiredOrExpiringSoonRule : LegacyDetectionRuleBase
    {
        public override RuleDescriptor Descriptor => new(
            RuleId: "R025",
            Name: "TLS Certificate Expired or Expiring Soon",
            Category: "TLS",
            Description: "TLS certificate expiry risk",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R025.Enabled",
            EnabledByDefault: true);
    }
}
