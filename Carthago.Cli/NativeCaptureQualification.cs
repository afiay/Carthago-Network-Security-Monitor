// SPDX-License-Identifier: MIT
using System.Globalization;
using Carthago.Services;
using Carthago.Engine.Rules;

namespace Carthago.Cli;

/// <summary>Explicitly authorized, time-limited observation; not a release qualification.</summary>
internal static class NativeCaptureQualification
{
    internal sealed record Options(string InterfaceId,int Seconds);
    internal sealed record Result(string Status,int RequestedSeconds,string? Failure,bool StopFailed,bool DisposeFailed,
        NativePcapCaptureSource.DriverStatistics Driver,PortableFrameQueue.Counters Pipeline,
        PortableMonitorSession.Snapshot? Monitor);

    internal static bool TryParse(string[] command,out Options? options)
    {
        options=null;
        if(command is not ["capture","qualify","--interface",var id,"--seconds",var seconds,"--authorized-test-time"]||
            string.IsNullOrWhiteSpace(id)||id.Length>512||id.StartsWith("--",StringComparison.Ordinal)||
            id.Contains("://",StringComparison.Ordinal)||id.Any(c=>char.IsControl(c)||
                char.GetUnicodeCategory(c)==System.Globalization.UnicodeCategory.Format)||
            !int.TryParse(seconds,NumberStyles.None,CultureInfo.InvariantCulture,out int duration)||duration is <1 or >60)
            return false;
        options=new(id,duration);return true;
    }

    internal static async Task<Result> RunAsync(Options options,CancellationToken token,
        Func<string,NativePcapCaptureSource>? create=null)
    {
        using var deadline=CancellationTokenSource.CreateLinkedTokenSource(token);
        deadline.CancelAfter(TimeSpan.FromSeconds(options.Seconds));
        var source=(create??(id=>new NativePcapCaptureSource(id)))(options.InterfaceId);
        var run=await PortableBufferedCaptureRun.RunAsync(source,
            PortableRuleCatalog.All.Select(r=>r.RuleId),deadline.Token).ConfigureAwait(false);
        string status=run.Status==PortableCaptureRun.Completion.Failed?"failed":
            token.IsCancellationRequested?"cancelled":
            run.Snapshot is null?"inconclusive_startup":
            run.Snapshot.Parsed==0?"inconclusive_no_parsed_frames":"sample_observed";
        return new(status,options.Seconds,run.Failure,run.StopFailed,run.DisposeFailed,
            source.FinalStatistics,run.Pipeline,run.Snapshot);
    }
}
