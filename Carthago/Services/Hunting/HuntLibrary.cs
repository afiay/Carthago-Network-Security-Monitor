// SPDX-License-Identifier: MIT
// File: Services/Hunting/HuntLibrary.cs
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Services.Hunting
{
    public static class HuntLibrary
    {
        public static IReadOnlyList<SavedHunt> Defaults { get; } = new[]
        {
            new SavedHunt { Name = "DNS long labels / tunneling", Query = new HuntQuery { RuleId = "R102" } },
            new SavedHunt { Name = "Suppressed or shadowed detections", Query = new HuntQuery { SuppressionStatus = DetectionSuppressionStatus.Shadowed } },
            new SavedHunt { Name = "External sink failures", Query = new HuntQuery { ExternalSinkStatus = ExternalSinkDeliveryStatus.Failed } },
            new SavedHunt { Name = "High-confidence detections", Query = new HuntQuery { MinConfidence = 0.75 } }
        };
    }
}
