// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services.ProtocolIntelligence
{
    // One instance per capture-owned TCP connection generation, under the flow lock.
    // Caller must establish both SYN anchors, complete untrimmed request framing,
    // default-credential classification and exact flow direction. No trust flag is emitted.
    internal sealed class HttpAuthenticationResponseCorrelation
    {
        private Guid _requestId;
        private uint _requestEnd;
        private DateTime _observedUtc;
        private bool _invalid;

        internal bool TryBegin(Guid requestId, uint sequence, int payloadLength, DateTime observedUtc)
        {
            if (_invalid || _requestId != Guid.Empty || requestId == Guid.Empty ||
                payloadLength is <= 0 or > 4096 || observedUtc.Kind != DateTimeKind.Utc)
            {
                Invalidate();
                return false;
            }
            _requestId = requestId;
            _requestEnd = unchecked(sequence + (uint)payloadLength);
            _observedUtc = observedUtc;
            return true;
        }

        // Call on every subsequent payload in either direction, including retransmissions.
        // A nonmatching payload consumes the candidate; no pipelining or reassembly.
        internal bool TryObservePayload(bool reverseDirection, bool ackPresent,
            uint acknowledgment, DateTime observedUtc, ReadOnlySpan<byte> payload,
            out Guid requestId, out int status)
        {
            requestId = Guid.Empty;
            status = 0;
            var pending = _requestId;
            var end = _requestEnd;
            var start = _observedUtc;
            Invalidate();
            if (pending == Guid.Empty || !reverseDirection || !ackPresent ||
                acknowledgment != end || observedUtc.Kind != DateTimeKind.Utc ||
                observedUtc < start || observedUtc - start > TimeSpan.FromSeconds(30) ||
                !HttpAuthenticationResponseInspector.TryInspect(payload, out status))
                return false;
            requestId = pending;
            return true;
        }

        // Call on gap, TLS transition, FIN/RST, or any connection ambiguity.
        // A new connection generation requires a new instance.
        internal void Invalidate()
        {
            _requestId = Guid.Empty;
            _requestEnd = 0;
            _observedUtc = default;
            _invalid = true;
        }
    }
}
