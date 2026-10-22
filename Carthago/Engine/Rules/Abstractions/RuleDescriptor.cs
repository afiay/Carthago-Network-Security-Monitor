// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/RuleDescriptor.cs
using Carthago.Models;
using Carthago.Engine.Rules;

namespace Carthago.Engine.Rules
{
    public sealed record RuleDescriptor(
        string RuleId,
        string Name,
        string Category,
        string Description,
        SeverityLevel DefaultSeverity,
        string ConfigKey,
        bool EnabledByDefault)
    {
        public bool IsPlanned { get; init; }
        public string? MissingTelemetry { get; init; }
    }
}
