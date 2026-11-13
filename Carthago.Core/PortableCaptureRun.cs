// SPDX-License-Identifier: MIT
namespace Carthago.Services;

/// <summary>
/// Single-owner pull source. Start returns a fixed portable link type.
/// Read returns null only at end of source; cancellation must unblock reads.
/// Frame bytes remain stable until the next read. Normalize DLT_NULL in the adapter.
/// Stop must tolerate partial startup and be safe after EOF or cancellation.
/// </summary>
internal interface IPortableCaptureSource : IAsyncDisposable
{
    ValueTask<int> StartAsync(CancellationToken token);
    ValueTask<PortableCaptureFrame?> ReadAsync(CancellationToken token);
    ValueTask StopAsync();
}

internal sealed record PortableCaptureFrame(byte[] Data,uint OriginalLength,DateTime TimestampUtc);

/// <summary>Owns one source for one run; serial pull, processing and observation delivery.</summary>
internal static class PortableCaptureRun
{
    internal enum Completion { EndOfSource, Cancelled, Failed }
    internal sealed record Result(Completion Status,string? Failure,bool StopFailed,bool DisposeFailed,
        PortableMonitorSession.Snapshot? Snapshot);

    internal static async Task<Result> RunAsync(IPortableCaptureSource source,
        IEnumerable<string> rules,CancellationToken token,bool allowEndOfSource=false,
        Action<PortableMonitorSession.FrameResult>? observe=null)
    {
        ArgumentNullException.ThrowIfNull(source);
        PortableMonitorSession? session=null;
        bool startAttempted=false,stopFailed=false,disposeFailed=false;
        var status=Completion.Failed;
        string? failure=null;
        string phase="configuration";
        try
        {
            token.ThrowIfCancellationRequested();
            ArgumentNullException.ThrowIfNull(rules);
            var selection=rules.Take(65).ToArray();
            if(selection.Length is <1 or >64 ||
                selection.Any(id=>!Carthago.Engine.Rules.PortableReplayDispatcher.Supports(id)) ||
                selection.Distinct(StringComparer.Ordinal).Count()!=selection.Length)
                throw new ArgumentException("Select distinct supported portable rule IDs.",nameof(rules));
            phase="startup";
            startAttempted=true;
            int link=await source.StartAsync(token).ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            session=new PortableMonitorSession(link,selection);
            while(true)
            {
                phase="read";
                token.ThrowIfCancellationRequested();
                var frame=await source.ReadAsync(token).ConfigureAwait(false);
                token.ThrowIfCancellationRequested();
                if(frame is null)
                {
                    status=allowEndOfSource?Completion.EndOfSource:Completion.Failed;
                    failure=allowEndOfSource?null:"unexpected_end_of_source";
                    break;
                }
                phase="processing";
                var result=session.Process(frame.Data,frame.OriginalLength,frame.TimestampUtc,token);
                phase="observation";
                observe?.Invoke(result);
            }
        }
        catch(OperationCanceledException) when(token.IsCancellationRequested)
        {
            status=Completion.Cancelled;
        }
        catch(Exception ex) when(ex is not OutOfMemoryException)
        {
            status=Completion.Failed;
            failure=phase+"_failed";
        }
        finally
        {
            // Cleanup has no cancelled token; no detached operations.
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
        if(stopFailed || disposeFailed)
        {
            status=Completion.Failed;
            failure??="cleanup_failed";
        }
        return new(status,failure,stopFailed,disposeFailed,session?.ReadSnapshot());
    }
}
