// SPDX-License-Identifier: MIT
// File: Services/InvestigationCopilot/LocalInvestigationCopilot.cs
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services.InvestigationCopilot
{
    public sealed class LocalInvestigationCopilot : IInvestigationCopilot
    {
        public Task<CopilotAnswer> AnswerAsync(CopilotContextPack context, string question, CancellationToken cancellationToken = default)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));
            var answer = new CopilotAnswer();
            var q = question ?? string.Empty;

            var topIncident = context.Incidents.FirstOrDefault();
            var topRisk = context.EntityRiskScores.OrderByDescending(r => r.Score).FirstOrDefault();
            var topEvents = context.Detections.Take(5).ToList();

            if (topIncident != null)
            {
                answer.Answer += $"Incident {topIncident.IncidentId} is classified as {topIncident.StoryType} with severity {topIncident.Severity}. ";
                answer.Citations.Add(new CopilotCitation { SourceType = "IncidentId", SourceId = topIncident.IncidentId, Claim = "Incident classification and severity" });
            }

            if (topRisk != null)
            {
                answer.Answer += $"The highest-risk entity is {topRisk.EntityId} with score {topRisk.Score} ({topRisk.Level}). ";
                answer.Citations.Add(new CopilotCitation { SourceType = "EntityId", SourceId = topRisk.EntityId, Claim = "Entity risk score" });
            }

            foreach (var evt in topEvents)
            {
                answer.Answer += $"Rule {evt.RuleId} contributed evidence: {evt.Summary}. ";
                answer.Citations.Add(new CopilotCitation { SourceType = "EventId", SourceId = evt.EventId, Claim = $"Detection {evt.RuleId}" });
            }

            if (context.MissingTelemetryWarnings.Count > 0)
                CopilotGuardrails.AddMissingEvidenceWarning(answer, "Some telemetry was missing; conclusions are limited to journaled evidence and available context.");
            if (answer.Citations.Count == 0)
            {
                answer.Answer = "No local Carthago facts were provided, so no investigation claim can be made.";
                answer.Warnings.Add("No cited EventId, RuleId, IncidentId, or EntityId is available.");
            }
            if (q.Contains("block", StringComparison.OrdinalIgnoreCase) || q.Contains("isolate", StringComparison.OrdinalIgnoreCase))
                answer.Warnings.Add("Containment actions require explicit human approval; the copilot can only recommend safe next steps.");

            return Task.FromResult(answer);
        }
    }
}
