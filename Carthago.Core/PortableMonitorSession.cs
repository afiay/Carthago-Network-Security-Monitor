// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;

namespace Carthago.Services;

/// <summary>
/// Host-independent frame processing for one capture source. The caller owns the
/// adapter, packet ordering and lifetime. No native capture, alert sink or host policy.
/// </summary>
internal sealed class PortableMonitorSession
{
    internal const int MaxFrameBytes = PortablePcapReader.MaxFrameBytes;
    internal sealed record Finding(string RuleId, string Method);
    internal sealed record FrameResult(long PacketNumber, DateTime TimestampUtc, string Status,
        bool ClockReset, IReadOnlyList<Finding> Findings);
    internal sealed record RuleCounters(string RuleId, long Evaluated, long Matches, long Suppressed);
    internal sealed record Snapshot(long Received, long Parsed, long Rejected, long CaptureTruncated,
        long ClockResets, long Matches, long Suppressed, IReadOnlyList<RuleCounters> Rules);

    private sealed class Counts { internal long Evaluated, Matches, Suppressed; }
    private readonly object _gate = new();
    private readonly string[] _rules;
    private readonly Dictionary<string, Counts> _counts;
    private readonly int _linkLayerType;
    private DateTime _now = DateTime.UnixEpoch;
    private DateTime? _previous;
    private PortablePacketProcessor _processor;
    private PortableReplayDispatcher _dispatcher = new();
    private long _received, _parsed, _rejected, _truncated, _resets, _matches, _suppressed;

    internal PortableMonitorSession(int linkLayerType, IEnumerable<string> rules)
    {
        if (linkLayerType is not (0 or 1 or 12 or 101 or 113 or 228 or 229 or 276))
            throw new ArgumentOutOfRangeException(nameof(linkLayerType));
        ArgumentNullException.ThrowIfNull(rules);
        // Bound even a lazy or adversarial selection before allocating state.
        _rules = rules.Take(65).ToArray();
        if (_rules.Length is < 1 or > 64 ||
            _rules.Any(id => !PortableReplayDispatcher.Supports(id)) ||
            _rules.Distinct(StringComparer.Ordinal).Count() != _rules.Length)
            throw new ArgumentException("Select distinct supported portable rule IDs.", nameof(rules));
        _linkLayerType = linkLayerType;
        _counts = _rules.ToDictionary(id => id, _ => new Counts(), StringComparer.Ordinal);
        _processor = new PortablePacketProcessor(() => _now);
    }

    // Caller retains frame ownership but must not mutate it during this synchronous call.
    // DLT_NULL input must already use the portable decoder's little-endian family bytes.
    // Each adapter must supply UTC and preserve capture order. One session per source.
    internal FrameResult Process(byte[] frame, uint originalLength, DateTime timestampUtc,
        CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(frame);
        if (timestampUtc.Kind != DateTimeKind.Utc)
            throw new ArgumentException("UTC timestamp required.", nameof(timestampUtc));
        if (frame.Length > MaxFrameBytes || originalLength < (uint)frame.Length)
            throw new ArgumentException("Invalid capture length.", nameof(frame));
        lock (_gate)
        {
            token.ThrowIfCancellationRequested();
            _received++;
            _now = timestampUtc;
            bool reset = _previous is DateTime previous && timestampUtc < previous;
            _previous = timestampUtc;
            if (reset)
            {
                _processor = new PortablePacketProcessor(() => _now);
                _dispatcher = new PortableReplayDispatcher();
                _resets++;
            }
            if (originalLength > (uint)frame.Length)
            {
                _truncated++;
                return new(_received, timestampUtc, "capture_truncated", reset, Array.Empty<Finding>());
            }
            var record = _processor.ParseFrame(frame, _linkLayerType);
            if (record is null)
            {
                _rejected++;
                return new(_received, timestampUtc, "rejected", reset, Array.Empty<Finding>());
            }
            _parsed++;
            var context = new PacketEvaluationContext(record, Sensitivity.Balanced, timestampUtc);
            var findings = new List<Finding>();
            foreach (var id in _rules)
            {
                var count = _counts[id];
                count.Evaluated++;
                var observation = _dispatcher.Evaluate(id, context, out var method);
                if (observation == WebSignatureObservation.Suppressed)
                { count.Suppressed++; _suppressed++; }
                if (observation != WebSignatureObservation.Match) continue;
                count.Matches++; _matches++;
                findings.Add(new(id, method));
            }
            return new(_received, timestampUtc, "parsed", reset, findings.AsReadOnly());
        }
    }

    internal Snapshot ReadSnapshot()
    {
        lock (_gate)
        {
            return new(_received, _parsed, _rejected, _truncated, _resets, _matches, _suppressed,
                Array.AsReadOnly(_rules.Select(id => new RuleCounters(id, _counts[id].Evaluated,
                    _counts[id].Matches, _counts[id].Suppressed)).ToArray()));
        }
    }
}
