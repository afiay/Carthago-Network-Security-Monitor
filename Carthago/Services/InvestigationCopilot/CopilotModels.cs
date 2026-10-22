// SPDX-License-Identifier: MIT
// File: Services/InvestigationCopilot/CopilotModels.cs
using System;
using System.Collections.Generic;
using Carthago.Analytics.Models;
using Carthago.Models;
using Carthago.Services.EntityGraph;
using Carthago.Services.Triage;

namespace Carthago.Services.InvestigationCopilot
{
    public sealed class CopilotCitation
    {
        public string SourceType { get; set; } = string.Empty;
        public string SourceId { get; set; } = string.Empty;
        public string Claim { get; set; } = string.Empty;
    }

    public sealed class CopilotAnswer
    {
        public string Answer { get; set; } = string.Empty;
        public List<CopilotCitation> Citations { get; set; } = new();
        public List<string> Warnings { get; set; } = new();
    }

    public sealed class CopilotContextPack
    {
        public List<DetectionEvent> Detections { get; set; } = new();
        public List<Incident> Incidents { get; set; } = new();
        public List<EntityRiskScore> EntityRiskScores { get; set; } = new();
        public List<TriageCase> TriageCases { get; set; } = new();
        public List<string> MissingTelemetryWarnings { get; set; } = new();
    }
}
