// SPDX-License-Identifier: MIT
// Internal RuleEngine test/runtime isolation hooks.
// Default production behavior remains unchanged.
using System;
using System.Threading;

namespace Carthago.Services
{
    public static partial class RuleEngine
    {
        private static readonly AsyncLocal<DetectionJournal?> DetectionJournalOverride = new();

        private static DetectionJournal ActiveDetectionJournal
            => DetectionJournalOverride.Value ?? DetectionJournal.Current;

        internal static IDisposable PushDetectionJournalForTests(
            DetectionJournal journal)
        {
            if (journal == null)
                throw new ArgumentNullException(nameof(journal));

            var previous = DetectionJournalOverride.Value;
            DetectionJournalOverride.Value = journal;
            return new DetectionJournalOverrideScope(previous);
        }

        private sealed class DetectionJournalOverrideScope : IDisposable
        {
            private readonly DetectionJournal? _previous;
            private int _disposed;

            internal DetectionJournalOverrideScope(DetectionJournal? previous)
                => _previous = previous;

            public void Dispose()
            {
                if (Interlocked.Exchange(ref _disposed, 1) != 0)
                    return;
                DetectionJournalOverride.Value = _previous;
            }
        }
    }
}
