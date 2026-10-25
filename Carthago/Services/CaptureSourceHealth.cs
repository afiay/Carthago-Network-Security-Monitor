// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services
{
    /// <summary>Source-side capture counters, before delivery to the shared UI queue.</summary>
    public sealed record CaptureSourceHealth(
        string Source, bool Running, long Observed, long Forwarded, long Dropped, string? Error)
    {
        public string ToDisplayText()
        {
            var name = string.IsNullOrWhiteSpace(Source) ? "Capture source" : Source;
            if (!Running)
                return string.IsNullOrWhiteSpace(Error)
                    ? $"{name} · stopped"
                    : $"{name} · stopped · {Error}";

            return $"{name} · active · observed {Observed} · forwarded {Forwarded} · dropped {Dropped}";
        }
    }
}
