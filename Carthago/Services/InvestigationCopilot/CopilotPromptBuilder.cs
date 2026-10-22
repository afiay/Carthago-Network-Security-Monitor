// SPDX-License-Identifier: MIT
// File: Services/InvestigationCopilot/CopilotPromptBuilder.cs
using System.Linq;
using System.Text;

namespace Carthago.Services.InvestigationCopilot
{
    public sealed class CopilotPromptBuilder
    {
        public string BuildLocalFactPack(CopilotContextPack context, string question)
        {
            var sb = new StringBuilder();
            sb.AppendLine("Question: " + question);
            foreach (var evt in context.Detections.Take(50)) sb.AppendLine($"Event {evt.EventId}: {evt.RuleId} {evt.Summary}");
            foreach (var incident in context.Incidents.Take(20)) sb.AppendLine($"Incident {incident.IncidentId}: {incident.Title} {incident.StoryType}");
            foreach (var risk in context.EntityRiskScores.Take(20)) sb.AppendLine($"Entity {risk.EntityId}: risk {risk.Score} {risk.Level}");
            return sb.ToString();
        }
    }
}
