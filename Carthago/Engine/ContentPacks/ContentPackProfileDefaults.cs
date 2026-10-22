// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/ContentPackProfileDefaults.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;

namespace Carthago.Engine.ContentPacks
{
    public sealed class ContentPackProfileDefaults
    {
        public string ProfileName { get; set; } = string.Empty;
        public RuleMode DefaultMode { get; set; } = RuleMode.Shadow;
        public double? ConfidenceFloorForAlert { get; set; }
        public bool DisableWhenTelemetryMissing { get; set; } = true;
        public List<string> RequiredApprovedAssets { get; set; } = new();
        public string Notes { get; set; } = string.Empty;
    }
}
