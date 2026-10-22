// SPDX-License-Identifier: MIT
// File: Services/InvestigationCopilot/CopilotGuardrails.cs
using System.Linq;

namespace Carthago.Services.InvestigationCopilot
{
    public static class CopilotGuardrails
    {
        public static bool HasCitations(CopilotAnswer answer) => answer.Citations.Count > 0 && answer.Citations.All(c => !string.IsNullOrWhiteSpace(c.SourceId));

        public static void AddMissingEvidenceWarning(CopilotAnswer answer, string message)
        {
            if (!answer.Warnings.Contains(message)) answer.Warnings.Add(message);
        }
    }
}
