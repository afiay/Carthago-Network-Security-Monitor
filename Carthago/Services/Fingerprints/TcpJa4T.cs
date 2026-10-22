// SPDX-License-Identifier: MIT
// File: Services/Fingerprints/TcpJa4T.cs
using System;
using System.Collections.Generic;

namespace Carthago.Services.Fingerprints
{
    /// <summary>
    /// Minimal TCP JA4T calculator that takes raw SYN option bytes.
    /// It does NOT depend on PacketDotNet types.
    /// </summary>
    public static class TcpJa4T
    {
        /// <param name="synOptions">Raw TCP options from SYN segment (may be null/empty).</param>
        /// <param name="window">Advertised window size.</param>
        /// <param name="mss">MSS if parsed elsewhere, otherwise null.</param>
        /// <param name="wscale">Window scale if parsed elsewhere, otherwise null.</param>
        /// <param name="sackPermitted">Whether SACK permitted option was present.</param>
        public static string Compute(byte[]? synOptions, int window, int? mss, int? wscale, bool sackPermitted)
        {
            // Very coarse canonicalization:
            // Format: "t:<win>:mss=<mss>;ws=<wscale>;sack=<0|1>;opt=<kind-seq>"
            var kinds = ParseOptionKinds(synOptions);
            var optSeq = string.Join("-", kinds);
            return $"t:{window}:mss={(mss?.ToString() ?? "0")};ws={(wscale?.ToString() ?? "0")};sack={(sackPermitted ? 1 : 0)};opt={optSeq}";
        }

        private static IEnumerable<int> ParseOptionKinds(byte[]? options)
        {
            if (options == null || options.Length == 0) yield break;
            for (int i = 0; i < options.Length;)
            {
                int kind = options[i];
                yield return kind;
                if (kind == 0) yield break;                // EOL
                if (kind == 1) { i++; continue; }          // NOP
                if (i + 1 >= options.Length) yield break;  // malformed
                int len = options[i + 1];
                if (len < 2) break;
                i += len;
            }
        }
    }
}
