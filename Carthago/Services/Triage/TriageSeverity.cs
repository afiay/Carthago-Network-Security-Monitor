// SPDX-License-Identifier: MIT
// File: Services/Triage/TriageSeverity.cs
namespace Carthago.Services.Triage
{
    public enum TriageSeverity
    {
        IgnoreCandidate,
        NeedsReview,
        InvestigateSoon,
        HighPriority,
        CriticalImmediate,
        PipelineHealthIssue
    }
}
