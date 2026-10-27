// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.LateralMovement
{
    public sealed class R081_ASREPRoastingHeuristicRule : TelemetryDetectionRuleBase
    {
        private readonly NetworkBatch071075Window _requests = new();
        public override RuleDescriptor Descriptor => new(
            RuleId: "R081",
            Name: "AS-REP Roasting Heuristic",
            Category: "LateralMovement",
            Description: "Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R081.Enabled",
            EnabledByDefault: true);

        public override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var r = context.Record;
            if (!NetworkBatch081085Evidence.KerberosAsRep(context, out var kdc, out var client)
                || !NetworkBatch076080Evidence.Classification(r, "KERBEROS", "AS_REP_NO_PREAUTH"))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            var threshold = RuleEngine.GetRuleIntSetting("R081", "Threshold", 3, 2, 4096);
            var windowSeconds = RuleEngine.GetRuleIntSetting("R081", "WindowSeconds", 60, 1, 86400);
            if (!_requests.Observe(client + "|" + kdc, r.Id.ToString("N"),
                context.TimestampUtc, threshold, TimeSpan.FromSeconds(windowSeconds)))
                return ValueTask.FromResult(RuleEvaluationResult.NoMatch(Descriptor.RuleId));
            return ValueTask.FromResult(NetworkBatch081085Evidence.Match(Descriptor, context,
                "Repeated classified Kerberos AS-REP replies without preauthentication; potential offline-guessing exposure, not proven password attack."));
        }
    }
}
