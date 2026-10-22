// SPDX-License-Identifier: MIT
// File: Services/Flow/FlowKey.cs

using System;

namespace Carthago.Services.Flow
{
    /// <summary>Unidirectional 5-tuple flow key.</summary>
    public readonly struct FlowKey : IEquatable<FlowKey>
    {
        public readonly string Src;
        public readonly int SrcPort;
        public readonly string Dst;
        public readonly int DstPort;
        public readonly string Proto; // "TCP" / "UDP"

        public FlowKey(string src, int sPort, string dst, int dPort, string proto)
        {
            Src = src ?? string.Empty;
            SrcPort = sPort;
            Dst = dst ?? string.Empty;
            DstPort = dPort;
            Proto = proto ?? string.Empty;
        }

        public FlowKey Reverse() => new(Dst, DstPort, Src, SrcPort, Proto);

        public bool Equals(FlowKey other) =>
            SrcPort == other.SrcPort && DstPort == other.DstPort &&
            string.Equals(Src, other.Src, StringComparison.Ordinal) &&
            string.Equals(Dst, other.Dst, StringComparison.Ordinal) &&
            string.Equals(Proto, other.Proto, StringComparison.Ordinal);

        public override bool Equals(object? obj) => obj is FlowKey fk && Equals(fk);

        public override int GetHashCode()
        {
            unchecked
            {
                int h = 17;
                h = h * 31 + Src.GetHashCode();
                h = h * 31 + SrcPort.GetHashCode();
                h = h * 31 + Dst.GetHashCode();
                h = h * 31 + DstPort.GetHashCode();
                h = h * 31 + Proto.GetHashCode();
                return h;
            }
        }

        public override string ToString() => $"{Src}:{SrcPort}->{Dst}:{DstPort}/{Proto}";
    }
}
