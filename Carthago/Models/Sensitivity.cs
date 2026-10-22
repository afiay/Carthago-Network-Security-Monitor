// SPDX-License-Identifier: MIT
// File: Models/Sensitivity.cs

namespace Carthago.Models
{
    public enum Sensitivity
    {
        Relaxed = 0,
        Balanced = 1,
        Aggressive = 2,
        Low = 3,
        Medium = 4,
        High = 5
    }

    public static class SensitivityExtensions
    {
        public static double Factor(this Sensitivity s) => s switch
        {
            Sensitivity.Aggressive => 0.8,
            Sensitivity.Balanced => 1.0,
            Sensitivity.Relaxed => 1.5,
            Sensitivity.High => 1.0,
            Sensitivity.Medium => 1.3,
            Sensitivity.Low => 1.6,
            _ => 1.0,
        };

        public static int AbuseIpdbThreshold(this Sensitivity s) => s switch
        {
            Sensitivity.Aggressive => 60,
            Sensitivity.Balanced => 75,
            Sensitivity.Relaxed => 85,
            Sensitivity.High => 70,
            Sensitivity.Medium => 80,
            Sensitivity.Low => 90,
            _ => 75,
        };

        public static bool TryParse(string? value, out Sensitivity s)
        {
            s = Sensitivity.Balanced;
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var v = value.Trim().ToLowerInvariant();
            switch (v)
            {
                case "relaxed": s = Sensitivity.Relaxed; break;
                case "balanced": s = Sensitivity.Balanced; break;
                case "aggressive": s = Sensitivity.Aggressive; break;
                case "low": s = Sensitivity.Low; break;
                case "medium": s = Sensitivity.Medium; break;
                case "high": s = Sensitivity.High; break;
                default: return false;
            }
            return true;
        }

        public static string ShortLabel(this Sensitivity s) => s switch
        {
            Sensitivity.Relaxed => "Relaxed",
            Sensitivity.Balanced => "Balanced",
            Sensitivity.Aggressive => "Aggressive",
            Sensitivity.Low => "Low",
            Sensitivity.Medium => "Medium",
            Sensitivity.High => "High",
            _ => "Balanced"
        };
    }
}
