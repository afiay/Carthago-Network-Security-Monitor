// SPDX-License-Identifier: MIT
// File: Services/Response/ResponseRecommendationEngine.cs
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Carthago.Analytics.Models;

namespace Carthago.Services.Response
{
    public sealed class ResponseRecommendationEngine
    {
        private readonly ResponseOptions _options;
        private readonly ResponseApprovalPolicy _policy;
        private readonly JsonSerializerOptions _json = new() { Converters = { new JsonStringEnumConverter() } };

        public ResponseRecommendationEngine(ResponseOptions? options = null, ResponseApprovalPolicy? policy = null)
        {
            _options = options ?? new ResponseOptions();
            _policy = policy ?? new ResponseApprovalPolicy();
        }

        public IReadOnlyList<ResponseAction> Recommend(Incident incident)
        {
            var actions = new List<ResponseAction>
            {
                New(ResponseActionType.ExportEvidenceBundle, ResponseActionSafety.Informational, false, "Export evidence bundle for review.", incident),
                New(ResponseActionType.CreateTimeline, ResponseActionSafety.Informational, false, "Create attack timeline for analyst handoff.", incident),
                New(ResponseActionType.AddWatchlistEntry, ResponseActionSafety.RecommendationOnly, false, "Watch the affected host/entity for follow-up detections.", incident)
            };

            if (incident.StoryType is AttackStoryType.ExploitToCallback or AttackStoryType.LateralMovementToExfiltration or AttackStoryType.OTSegmentViolation)
            {
                actions.Add(New(ResponseActionType.RecommendIsolateHost, ResponseActionSafety.RecommendationOnly, false, "Recommend host isolation after evidence review.", incident));
                actions.Add(New(ResponseActionType.IsolateHost, ResponseActionSafety.Destructive, true, "Actual isolation requires explicit approval.", incident));
            }
            if (incident.StoryType is AttackStoryType.DnsC2Suspicion or AttackStoryType.CloudExfiltrationSuspicion)
                actions.Add(New(ResponseActionType.RecommendBlockDomain, ResponseActionSafety.RecommendationOnly, false, "Recommend blocking the suspicious domain only after validation.", incident));
            return actions;
        }

        public async Task<ResponseExecutionRecord> PersistRecommendationAsync(ResponseAction action)
        {
            Directory.CreateDirectory(_options.DirectoryPath);
            var record = new ResponseExecutionRecord { Action = action, Status = "Recommended" };
            var path = Path.Combine(_options.DirectoryPath, $"response-actions-{DateTime.UtcNow:yyyy-MM}.jsonl");
            await File.AppendAllTextAsync(path, JsonSerializer.Serialize(record, _json) + Environment.NewLine).ConfigureAwait(false);
            return record;
        }

        public async Task<ResponseExecutionRecord> ExecuteAsync(ResponseAction action, bool approved = false)
        {
            if ((action.RequiresApproval || action.Safety == ResponseActionSafety.Destructive) && _policy.RequireApprovalForDestructiveActions && !approved)
            {
                action.Result = "Rejected: explicit approval required";
                return await PersistRecommendationAsync(action).ConfigureAwait(false);
            }
            action.ApprovedUtc = approved ? DateTime.UtcNow : action.ApprovedUtc;
            action.ExecutedUtc = DateTime.UtcNow;
            action.Result = action.Safety == ResponseActionSafety.Destructive ? "Execution stubbed; external enforcement adapter not configured" : "Executed locally";
            return await PersistRecommendationAsync(action).ConfigureAwait(false);
        }

        private static ResponseAction New(ResponseActionType type, ResponseActionSafety safety, bool approval, string reason, Incident incident) => new()
        {
            ActionType = type,
            Safety = safety,
            RequiresApproval = approval,
            Reason = reason,
            SourceIncidentId = incident.IncidentId,
            SourceEventId = incident.RelatedEventIds.Count > 0 ? incident.RelatedEventIds[0] : null,
            SourceRuleId = incident.RelatedRuleIds.Count > 0 ? incident.RelatedRuleIds[0] : null,
            RollbackGuidance = safety == ResponseActionSafety.Destructive ? "Rollback must be performed in the external enforcement system that executed the action." : "No rollback required for informational recommendation."
        };
    }
}
