// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Analytics.Models
{
    public sealed class MlFeatureWindow
    {
        public DateTime WindowStartUtc { get; set; }
        public DateTime WindowEndUtc { get; set; }
        public string SourceIp { get; set; } = string.Empty;

        public float OutboundBytes { get; set; }
        public float UniqueDestinationCount { get; set; }
        public float UniquePortCount { get; set; }
        public float RuleHitCount { get; set; }
        public float SeverityWeightedRuleCount { get; set; }
        public float NewDestinationCount { get; set; }
        public float NewAsnCount { get; set; }
        public float NewCountryCount { get; set; }
        public float RareFingerprintCount { get; set; }
        public float ThreatIntelHitCount { get; set; }
        public float HourOfDay { get; set; }
        public float DayOfWeek { get; set; }
    }
}
