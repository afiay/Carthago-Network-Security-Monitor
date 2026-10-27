// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services.Baseline;

namespace Carthago.Tests;

internal static class AssetBatch061065Context
{
    internal static readonly DateTime T0 = DateTime.UtcNow.AddMinutes(-10);
    internal static RuleEvaluationContext At(int second, string source="10.61.0.10",
        string destination="8.8.8.8",int? sourcePort=50000,int? destinationPort=443,
        ushort? flags=2,string protocol="TCP",string? app="TLS",string? info=null,
        string? process=null,string? service=null,string? asn=null)
        => new(new TrafficRecord
        {
            Source=source,Destination=destination,SourcePort=sourcePort,DestinationPort=destinationPort,
            TcpFlags=flags,Protocol=protocol,ApplicationProtocol=app,Info=info,
            ProcessName=process,ApplicationService=service,WhoisASN=asn
        },Sensitivity.Balanced,T0.AddSeconds(second));

    internal static IDisposable Unready()
    {
        var dir=Path.Combine(Path.GetTempPath(),"carthago-asset-unready-"+Guid.NewGuid().ToString("N"));
        var store=new BaselineStore(new BaselineOptions { DirectoryPath=dir, LearningMode=true });
        return new Cleanup(BaselineStore.UseScoped(store),dir);
    }

    // Install AsyncLocal scope synchronously in the calling test context.
    // Installing it after an await inside Ready() would isolate it to that
    // callee's ExecutionContext and the test would see the live default store.
    internal static Task<IDisposable> Ready()
    {
        var dir=Path.Combine(Path.GetTempPath(),"carthago-asset-batch-"+Guid.NewGuid().ToString("N"));
        var store=new BaselineStore(new BaselineOptions
        {
            DirectoryPath=dir,MinimumObservations=1,MinimumDistinctKeys=1,
            MinimumObservationSpan=TimeSpan.Zero,MaximumObservationAge=TimeSpan.FromDays(2)
        });
        var scope = new Cleanup(BaselineStore.UseScoped(store), dir);
        return InitializeReadyAsync(store, scope);
    }

    private static async Task<IDisposable> InitializeReadyAsync(BaselineStore store, Cleanup scope)
    {
        await store.ObserveAsync(new BaselineObservation("test_seed","test","ready",
            DateTime.UtcNow.AddMinutes(-1),"Synthetic isolated test readiness"));
        if(!(await store.GetReadinessAsync()).IsReady)
            throw new InvalidOperationException("Isolated baseline fixture is not ready.");
        return scope;
    }
    private sealed class Cleanup : IDisposable
    {
        private readonly IDisposable _scope;
        private readonly string _dir;
        internal Cleanup(IDisposable scope,string dir){_scope=scope;_dir=dir;}
        public void Dispose()
        {
            _scope.Dispose();
            if(Directory.Exists(_dir)) Directory.Delete(_dir,true);
        }
    }
}
