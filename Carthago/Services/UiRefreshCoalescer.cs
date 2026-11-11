using System.Threading;

namespace Carthago.Services
{
    /// <summary>Bounds queued UI refresh work without losing an update arriving mid-refresh.</summary>
    public sealed class UiRefreshCoalescer
    {
        private int _scheduled;
        private long _version;

        public long Version => Interlocked.Read(ref _version);

        public bool Request()
        {
            Interlocked.Increment(ref _version);
            return Interlocked.CompareExchange(ref _scheduled, 1, 0) == 0;
        }

        /// <summary>Returns true when one more refresh needs to be posted.</summary>
        public bool Complete(long handledVersion)
        {
            Volatile.Write(ref _scheduled, 0);
            return Version != handledVersion &&
                Interlocked.CompareExchange(ref _scheduled, 1, 0) == 0;
        }
    }
}
