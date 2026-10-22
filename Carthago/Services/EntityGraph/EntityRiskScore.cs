// SPDX-License-Identifier: MIT
// File: Services/EntityGraph/EntityRiskScore.cs
using System;
using System.Collections.Generic;

namespace Carthago.Services.EntityGraph
{
    public enum EntityRiskLevel
    {
        Low,
        Medium,
        High,
        Critical
    }

    public sealed class EntityRiskScore
    {
        public string EntityId { get; set; } = string.Empty;
        public int Score { get; set; }
        public EntityRiskLevel Level { get; set; }
        public DateTime CalculatedUtc { get; set; } = DateTime.UtcNow;
        public List<EntityRiskReason> Reasons { get; set; } = new();

        public static EntityRiskLevel LevelFor(int score) => score switch
        {
            >= 75 => EntityRiskLevel.Critical,
            >= 50 => EntityRiskLevel.High,
            >= 25 => EntityRiskLevel.Medium,
            _ => EntityRiskLevel.Low
        };
    }
}
