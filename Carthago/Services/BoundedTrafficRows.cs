using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace Carthago.Services
{
    /// <summary>One grid notification per capture batch; newest records are shown first.</summary>
    public sealed class BoundedTrafficRows<T> : ObservableCollection<T>
    {
        public void PrependBatch(IReadOnlyList<T> records, int capacity)
        {
            if (records == null) throw new ArgumentNullException(nameof(records));
            if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
            if (records.Count == 0) return;

            CheckReentrancy();
            // Capture batches arrive oldest-first; the visible grid is newest-first.
            for (var i = records.Count - 1; i >= 0; i--)
                Items.Insert(0, records[i]);
            while (Items.Count > capacity)
                Items.RemoveAt(Items.Count - 1);

            OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
            OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
            OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
        }
    }
}
