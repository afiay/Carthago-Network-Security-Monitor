// SPDX-License-Identifier: MIT
using System.Threading.Channels;
using Carthago.Engine.Rules;

namespace Carthago.Services;

/// <summary>Single producer/single consumer bounded handoff. Limits include the in-flight frame.</summary>
internal sealed class PortableFrameQueue
{
    internal sealed record Counters(long Captured,long Accepted,long DroppedCapacity,long DroppedInvalid,
        long Processed,long Abandoned,int Pending,long PendingBytes,int PeakPending,long PeakPendingBytes);
    private readonly object _gate=new();
    private readonly Channel<PortableCaptureFrame> _channel;
    private readonly int _maxPackets;
    private readonly long _maxBytes;
    private long _captured,_accepted,_capacity,_invalid,_processed,_abandoned,_bytes,_peakBytes;
    private int _pending,_peak;
    private bool _completed;

    internal PortableFrameQueue(int maxPackets,long maxBytes)
    {
        if(maxPackets is <1 or >4096) throw new ArgumentOutOfRangeException(nameof(maxPackets));
        if(maxBytes is <1 or >64L*1024*1024) throw new ArgumentOutOfRangeException(nameof(maxBytes));
        _maxPackets=maxPackets;_maxBytes=maxBytes;
        _channel=Channel.CreateBounded<PortableCaptureFrame>(new BoundedChannelOptions(maxPackets)
        {
            SingleReader=true,SingleWriter=true,FullMode=BoundedChannelFullMode.Wait,
            AllowSynchronousContinuations=false
        });
    }

    // The source owns its input. Copy only after capacity and metadata checks.
    internal bool Offer(PortableCaptureFrame frame)
    {
        ArgumentNullException.ThrowIfNull(frame);
        lock(_gate)
        {
            if(_completed) throw new InvalidOperationException("Queue completed.");
            _captured++;
            if(frame.Data is null || frame.Data.Length>PortableMonitorSession.MaxFrameBytes ||
                frame.OriginalLength<(uint)frame.Data.Length || frame.TimestampUtc.Kind!=DateTimeKind.Utc)
            { _invalid++;return false; }
            if(_pending>=_maxPackets || frame.Data.Length>_maxBytes-_bytes)
            { _capacity++;return false; }
            var owned=new PortableCaptureFrame((byte[])frame.Data.Clone(),frame.OriginalLength,frame.TimestampUtc);
            if(!_channel.Writer.TryWrite(owned)) throw new InvalidOperationException("Queue capacity invariant.");
            _accepted++;_pending++;_bytes+=owned.Data.Length;
            _peak=Math.Max(_peak,_pending);_peakBytes=Math.Max(_peakBytes,_bytes);
            return true;
        }
    }

    internal IAsyncEnumerable<PortableCaptureFrame> ReadAllAsync()=>_channel.Reader.ReadAllAsync();

    // Exactly once for each dequeued frame, including an unsuccessful processing attempt.
    internal void Finish(PortableCaptureFrame frame,bool processed)
    {
        lock(_gate)
        {
            if(_pending<=0 || _bytes<frame.Data.Length) throw new InvalidOperationException("Queue accounting invariant.");
            _pending--;_bytes-=frame.Data.Length;
            if(processed)_processed++;else _abandoned++;
        }
    }

    internal void Complete()
    {
        lock(_gate)
        {
            if(_completed)return;
            _completed=true;_channel.Writer.TryComplete();
        }
    }

    internal Counters ReadCounters()
    {
        lock(_gate)return new(_captured,_accepted,_capacity,_invalid,_processed,_abandoned,
            _pending,_bytes,_peak,_peakBytes);
    }
}

/// <summary>One owned pull source, one ordered consumer, bounded copied frame handoff.</summary>
internal static class PortableBufferedCaptureRun
{
    internal sealed record Result(PortableCaptureRun.Completion Status,string? Failure,bool StopFailed,bool DisposeFailed,
        PortableMonitorSession.Snapshot? Snapshot,PortableFrameQueue.Counters Pipeline);

    internal static async Task<Result> RunAsync(IPortableCaptureSource source,IEnumerable<string> rules,
        CancellationToken token,int maxPackets=256,long maxBytes=16L*1024*1024,
        bool allowEndOfSource=false,Action<PortableMonitorSession.FrameResult>? observe=null)
    {
        ArgumentNullException.ThrowIfNull(source);
        // Validate queue options before taking lifetime ownership.
        var queue=new PortableFrameQueue(maxPackets,maxBytes);
        PortableMonitorSession? session=null;
        bool startAttempted=false,stopFailed=false,disposeFailed=false;
        string? failure=null,producerFailure=null,consumerFailure=null;
        var status=PortableCaptureRun.Completion.Failed;
        string phase="configuration";
        using var stopRead=CancellationTokenSource.CreateLinkedTokenSource(token);
        try
        {
            token.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(rules);
            var selection=rules.Take(65).ToArray();
            if(selection.Length is <1 or >64 || selection.Any(id=>!PortableReplayDispatcher.Supports(id)) ||
                selection.Distinct(StringComparer.Ordinal).Count()!=selection.Length)
                throw new ArgumentException("Select distinct supported portable rule IDs.",nameof(rules));
            phase="startup";startAttempted=true;
            int link=await source.StartAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            session=new PortableMonitorSession(link,selection);
            var active=session;
            // Run consumer separately even when a source returns synchronously.
            // No run cancellation token on consumer: graceful shutdown drains accepted frames.
            var consumer=Task.Run(async ()=>
            {
                await foreach(var frame in queue.ReadAllAsync().ConfigureAwait(false))
                {
                    bool processed=false;
                    try
                    {
                        if(consumerFailure is not null)continue;
                        var result=active.Process(frame.Data,frame.OriginalLength,frame.TimestampUtc);
                        processed=true;
                        observe?.Invoke(result);
                    }
                    catch(Exception ex) when(ex is not OutOfMemoryException)
                    {
                        consumerFailure=processed?"observation_failed":"processing_failed";
                        stopRead.Cancel();
                    }
                    finally { queue.Finish(frame,processed); }
                }
            });
            phase="read";
            try
            {
                while(true)
                {
                    stopRead.Token.ThrowIfCancellationRequested();
                    var frame=await source.ReadAsync(stopRead.Token).ConfigureAwait(false);
                    // If a read completes concurrently with cancellation, account for
                    // the returned frame before stopping acquisition.
                    if(frame is null)
                    {
                        if(!stopRead.IsCancellationRequested && !allowEndOfSource)
                            producerFailure="unexpected_end_of_source";
                        break;
                    }
                    queue.Offer(frame);
                }
            }
            catch(OperationCanceledException) when(stopRead.IsCancellationRequested) { }
            catch(Exception ex) when(ex is not OutOfMemoryException) { producerFailure="read_failed"; }
            finally
            {
                queue.Complete();
                await consumer.ConfigureAwait(false);
            }
            failure=consumerFailure??producerFailure;
            status=failure is not null?PortableCaptureRun.Completion.Failed:
                token.IsCancellationRequested?PortableCaptureRun.Completion.Cancelled:PortableCaptureRun.Completion.EndOfSource;
        }
        catch(OperationCanceledException) when(token.IsCancellationRequested)
        { status=PortableCaptureRun.Completion.Cancelled; }
        catch(Exception ex) when(ex is not OutOfMemoryException)
        { status=PortableCaptureRun.Completion.Failed;failure=phase+"_failed"; }
        finally
        {
            queue.Complete();
            try
            {
                if(startAttempted)
                {
                    try { await source.StopAsync().ConfigureAwait(false); }
                    catch(Exception ex) when(ex is not OutOfMemoryException) { stopFailed=true; }
                }
            }
            finally
            {
                try { await source.DisposeAsync().ConfigureAwait(false); }
                catch(Exception ex) when(ex is not OutOfMemoryException) { disposeFailed=true; }
            }
        }
        if(stopFailed||disposeFailed)
        { status=PortableCaptureRun.Completion.Failed;failure??="cleanup_failed"; }
        return new(status,failure,stopFailed,disposeFailed,session?.ReadSnapshot(),queue.ReadCounters());
    }
}
