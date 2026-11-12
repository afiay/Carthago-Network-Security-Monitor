using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Linq;

namespace Carthago.Services
{
    /// <summary>One grid notification per capture batch; newest records are shown first.</summary>
    public sealed class BoundedTrafficRows<T> : ObservableCollection<T>
    {
        // WPF requires the Items collection to agree with every published
        // CollectionChanged event. Deferred capture batches therefore live in
        // a private buffer until NotifyReset publishes the complete snapshot.
        private List<T>? _stagedItems;

        public void PrependBatch(
            IReadOnlyList<T> records,
            int capacity,
            bool notifyCollectionChanged = true)
        {
            if (records == null) throw new ArgumentNullException(nameof(records));
            if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
            if (records.Count == 0) return;

            CheckReentrancy();
            _stagedItems ??= new List<T>(Items);

            // Capture batches arrive oldest-first; retained rows are newest-first.
            for (var i = 0; i < records.Count; i++)
                _stagedItems.Insert(0, records[i]);
            while (_stagedItems.Count > capacity)
                _stagedItems.RemoveAt(_stagedItems.Count - 1);

            if (notifyCollectionChanged)
                NotifyReset();
        }

        /// <summary>
        /// Returns the newest retained rows, including batches waiting for the
        /// next grid refresh, without exposing the mutable staging buffer.
        /// </summary>
        public IReadOnlyList<T> GetRetainedSnapshot()
            => _stagedItems?.ToArray() ?? Items.ToArray();

        public void NotifyReset()
        {
            CheckReentrancy();

            if (_stagedItems is not null)
            {
                // Publish all staged rows in the same dispatcher call stack as
                // the Reset event, so an ItemsControl can never observe a
                // partially updated or silently changed Items collection.
                Items.Clear();
                foreach (var item in _stagedItems)
                    Items.Add(item);
                _stagedItems = null;
            }

            OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
            OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }
}
