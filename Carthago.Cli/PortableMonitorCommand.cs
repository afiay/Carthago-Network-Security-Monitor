// SPDX-License-Identifier: MIT
using System.Globalization;
using System.Text.Json;
using Carthago.Engine.Rules;
using Carthago.Services;

namespace Carthago.Cli;

/// <summary>Explicit foreground test host with optional session control. Optional bounded journal; no active response.</summary>
internal static class PortableMonitorCommand
{
    internal sealed record Options(string InterfaceId,string[] Rules,int StatusSeconds,int MaxPackets,long MaxBytes,bool EnableControl=false,bool AllowStop=false,string? JournalDirectory=null);

    internal static bool TryParse(string[] command,out Options? options)
    {
        options=null;
        if(command is not ["monitor","run",..])return false;
        string? id=null,journalDirectory=null;string[]? rules=null;bool authorized=false,control=false,allowStop=false;
        int seconds=5,packets=256;long bytes=16L*1024*1024;
        var seen=new HashSet<string>(StringComparer.Ordinal);
        for(int i=2;i<command.Length;i++)
        {
            string key=command[i];
            if(!seen.Add(key))return false;
            if(key=="--authorized-test-time"){authorized=true;continue;}
            if(key=="--enable-portable-control"){control=true;continue;}
            if(key=="--allow-portable-stop"){allowStop=true;continue;}
            if(++i>=command.Length)return false;
            string value=command[i];
            switch(key)
            {
                case "--interface":
                    if(string.IsNullOrWhiteSpace(value)||value.Length>512||value.StartsWith("--",StringComparison.Ordinal)||
                        value.Contains("://",StringComparison.Ordinal)||value.Any(c=>char.IsControl(c)||
                            char.GetUnicodeCategory(c)==UnicodeCategory.Format))return false;
                    id=value;break;
                case "--journal-directory":
                    if(!PortableMonitorJournal.ValidPath(value))return false;
                    journalDirectory=value;break;
                case "--rules":
                    if(value.Length>1024)return false;
                    rules=value.Split(',');
                    if(rules.Length is <1 or >64||rules.Any(r=>!PortableReplayDispatcher.Supports(r))||
                        rules.Distinct(StringComparer.Ordinal).Count()!=rules.Length)return false;
                    break;
                case "--status-seconds":
                    if(!int.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out seconds)||seconds is <1 or >60)return false;
                    break;
                case "--max-packets":
                    if(!int.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out packets)||packets is <1 or >4096)return false;
                    break;
                case "--max-bytes":
                    if(!long.TryParse(value,NumberStyles.None,CultureInfo.InvariantCulture,out bytes)||bytes is <1 or >67108864)return false;
                    break;
                default:return false;
            }
        }
        if(!authorized||id is null||rules is null||(allowStop&&!control))return false;
        options=new(id,rules,seconds,packets,bytes,control,allowStop,journalDirectory);return true;
    }

    private static readonly JsonSerializerOptions JsonOptions=new(JsonSerializerDefaults.Web);

    internal static async Task<int> RunAsync(Options options,TextWriter output,bool json,CancellationToken token,
        Func<string,NativePcapCaptureSource>? create=null,TimeSpan? reportInterval=null)
    {
        using var stop=CancellationTokenSource.CreateLinkedTokenSource(token);
        using var reportStop=new CancellationTokenSource();
        var source=(create??(id=>new NativePcapCaptureSource(id)))(options.InterfaceId);
        var sessionId=Guid.NewGuid();
        using var journal=options.JournalDirectory is null?null:new PortableMonitorJournal(options.JournalDirectory,sessionId);
        long sequence=0;
        var outputGate=new object();
        PortableBufferedCaptureRun.Progress? progress=null;
        bool reportingFailed=false,controlFailed=false;
        using var controlStop=new CancellationTokenSource();
        Task controlTask=Task.CompletedTask;
        void Emit<T>(string eventType,T data,string text)
        {
            lock(outputGate)
            {
                var line=JsonSerializer.Serialize(new { schemaVersion=1,mode="portable_foreground",
                    eventType,sessionId,sequence=++sequence,observedUtc=DateTime.UtcNow,detectionValidation="not_assessed",
                    sourceHealth="not_assessed",data },JsonOptions);
                journal?.Append(line);
                output.WriteLine(json?line:text);
                output.Flush();
            }
        }
        // Periodic snapshots are independent observations, not a transaction across
        // queue and monitor. No native pcap calls from this reporting task.
        async Task ReportAsync()
        {
            using var timer=new PeriodicTimer(reportInterval??TimeSpan.FromSeconds(options.StatusSeconds));
            try
            {
                while(await timer.WaitForNextTickAsync(reportStop.Token).ConfigureAwait(false))
                {
                    var p=Volatile.Read(ref progress);
                    if(p is null)continue;
                    var monitor=p.Monitor();var pipeline=p.Pipeline();
                    Emit("health",new { monitor,pipeline,driverStatistics="final_only" },
                        $"Health: captured={pipeline.Captured}; processed={pipeline.Processed}; matches={monitor.Matches}; capacityDrops={pipeline.DroppedCapacity}");
                }
            }
            catch(OperationCanceledException) when(reportStop.IsCancellationRequested){}
            catch(Exception ex) when(ex is not OutOfMemoryException)
            { reportingFailed=true;stop.Cancel(); }
        }
        var reporting=ReportAsync();
        PortableBufferedCaptureRun.Result run;
        try
        {
            // Native startup/read may be synchronous. Keep reporting independent.
            run=await Task.Run(()=>PortableBufferedCaptureRun.RunAsync(source,options.Rules,stop.Token,
                options.MaxPackets,options.MaxBytes,observe:frame=>
                {
                    foreach(var finding in frame.Findings)
                        Emit("finding",new { frame.PacketNumber,frame.TimestampUtc,finding.RuleId,finding.Method },
                            $"Observation: {finding.RuleId} packet={frame.PacketNumber} {frame.TimestampUtc:O} {finding.Method}");
                },started:p=>
                {
                    if(options.EnableControl)
                    {
                        var pipe=PortableMonitorControl.CreateServer(sessionId);
                        controlTask=PortableMonitorControl.ServeAsync(pipe,sessionId,p,options.AllowStop,
                            stop.Token,()=>stop.Cancel(),controlStop.Token,()=>{controlFailed=true;stop.Cancel();});
                    }
                    Emit("started",new { rules=options.Rules,options.StatusSeconds,options.MaxPackets,options.MaxBytes,
                        controlEnabled=options.EnableControl,stopAllowed=options.AllowStop,journalEnabled=journal is not null },
                        $"Portable monitor started: {string.Join(",",options.Rules)}; session={sessionId:D}; control={options.EnableControl}; stopAllowed={options.AllowStop}");
                    Volatile.Write(ref progress,p);
                })).ConfigureAwait(false);
        }
        finally
        {
            reportStop.Cancel();
            controlStop.Cancel();
            await reporting.ConfigureAwait(false);
            await controlTask.ConfigureAwait(false);
        }
        string status=reportingFailed||controlFailed||run.Status==PortableCaptureRun.Completion.Failed?"failed":
            token.IsCancellationRequested?"cancelled":"stopped";
        Emit("stopped",new { status,failure=reportingFailed?"reporting_failed":controlFailed?"control_failed":run.Failure,
            run.StopFailed,run.DisposeFailed,driver=source.FinalStatistics,pipeline=run.Pipeline,monitor=run.Snapshot },
            $"Portable monitor {status}: captured={run.Pipeline.Captured}; processed={run.Pipeline.Processed}; abandoned={run.Pipeline.Abandoned}");
        return status=="failed"?CliApplication.DataError:status=="cancelled"?CliApplication.Cancelled:CliApplication.Success;
    }
}
