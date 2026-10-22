// SPDX-License-Identifier: MIT
// File: Services/Response/ResponseModels.cs
using System;
using System.Collections.Generic;

namespace Carthago.Services.Response
{
    public enum ResponseActionType
    {
        OpenIncident,
        AddAnalystNote,
        MarkForReview,
        ExportEvidenceBundle,
        CreateTimeline,
        AddWatchlistEntry,
        IncreaseHostRiskTemporarily,
        RecommendBlockDomain,
        RecommendBlockIp,
        RecommendIsolateHost,
        RecommendDisableExternalSink,
        RecommendDisableNoisyRule,
        RecommendEnablePacketCapture,
        RecommendSwitchProfile,
        BlockIp,
        BlockDomain,
        IsolateHost,
        DisableRule,
        ChangeProfile,
        ClearBaseline,
        DeleteFeedback,
        PurgeJournalOutbox
    }

    public enum ResponseActionSafety
    {
        Informational,
        RecommendationOnly,
        ApprovalRequired,
        Destructive
    }

    public sealed class ResponseAction
    {
        public string ActionId { get; set; } = Guid.NewGuid().ToString("N");
        public ResponseActionType ActionType { get; set; }
        public ResponseActionSafety Safety { get; set; }
        public bool RequiresApproval { get; set; }
        public string Reason { get; set; } = string.Empty;
        public string? SourceIncidentId { get; set; }
        public string? SourceEventId { get; set; }
        public string? SourceRuleId { get; set; }
        public string? SourceEntityId { get; set; }
        public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
        public DateTime? ApprovedUtc { get; set; }
        public DateTime? ExecutedUtc { get; set; }
        public string Result { get; set; } = "Created";
        public string? RollbackGuidance { get; set; }
    }

    public sealed class ResponsePlaybook
    {
        public string PlaybookId { get; set; } = Guid.NewGuid().ToString("N");
        public string Name { get; set; } = string.Empty;
        public List<ResponseAction> Actions { get; set; } = new();
    }

    public sealed class ResponseExecutionRecord
    {
        public string ExecutionId { get; set; } = Guid.NewGuid().ToString("N");
        public ResponseAction Action { get; set; } = new();
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string Status { get; set; } = string.Empty;
    }

    public sealed class ResponseApprovalPolicy
    {
        public bool RequireApprovalForDestructiveActions { get; set; } = true;
    }

    public sealed class ResponseOptions
    {
        public string DirectoryPath { get; set; } = System.IO.Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Carthago", "response");
    }
}
