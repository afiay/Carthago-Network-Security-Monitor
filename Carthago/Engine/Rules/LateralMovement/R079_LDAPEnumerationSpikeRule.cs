// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R079_LDAPEnumerationSpikeRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _observations = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R079", Name: "LDAP Enumeration Spike", Category: "LateralMovement",
            Description: "Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R079.Enabled", EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext c, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var r = c.Record;
            if (r.DestinationPort is not (389 or 636 or 3268 or 3269)
                || !NetworkBatch076080Evidence.InternalTcp(c, r.DestinationPort.Value, out var src, out var dst)
                || !NetworkBatch076080Evidence.Classification(r, "LDAP", "SEARCH_REQUEST"))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold = RuleEngine.GetRuleIntSetting("R079", "Threshold", 40, 2, 4096);
            var seconds = RuleEngine.GetRuleIntSetting("R079", "WindowSeconds", 60, 1, 86400);
            if (!_observations.Observe(src + "|" + dst + "|" + r.DestinationPort,
                r.Id.ToString("N"), c.TimestampUtc, threshold, TimeSpan.FromSeconds(seconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch076080Evidence.Result(Descriptor, c,
                "High rate of independently classified LDAP search requests to one internal directory endpoint; authorization unknown."));
        }
    }
}
