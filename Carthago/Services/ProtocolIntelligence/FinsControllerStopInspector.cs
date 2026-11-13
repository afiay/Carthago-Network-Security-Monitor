// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    // Exact FINS/UDP local CPU-unit STOP (0402), response requested.
    // A request does not establish an accepted command or stopped CPU.
    internal static class FinsControllerStopInspector
    {
        internal static bool TryInspect(ReadOnlySpan<byte> p)
            => p.Length == 12 && p[0] == 0x80 && p[1] == 0 &&
                p[2] == 2 && p[3] == 0 && p[5] == 0 &&
                p[6] == 0 && p[8] == 0 &&
                p[4] is >= 1 and <= 254 && p[7] is >= 1 and <= 254 &&
                p[4] != p[7] && p[10] == 4 && p[11] == 2;
    }
}
