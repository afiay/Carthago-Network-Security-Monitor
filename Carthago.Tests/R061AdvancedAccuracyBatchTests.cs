// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.AssetInventory;
using Xunit;
namespace Carthago.Tests;
public sealed class R061AdvancedAccuracyBatchTests
{
    private readonly R061_SensitiveHostCommunicatingExternallyRule _rule=new();
    private async Task<bool> Seen(int s=0,string dst="8.8.8.8",int? port=1433,string? info="SQL Server outbound",string? app="TLS",string protocol="TCP")
        => (await _rule.EvaluateAsync(AssetBatch061065Context.At(s,destination:dst,sourcePort:port,
            flags:null,info:info,app:app,protocol:protocol))).Matched;
    [Fact] public async Task Corroborated_Sql_Source_Egress_Matches(){Assert.True(await Seen());}
    [Fact] public async Task Dns_Resolver_Is_Not_A_Sensitive_Host(){Assert.False(await Seen(port:50000,app:"DNS",protocol:"UDP",info:null));}
    [Fact] public async Task Sensitive_Destination_Port_Does_Not_Prove_Source_Role(){Assert.False((await _rule.EvaluateAsync(AssetBatch061065Context.At(0,destinationPort:1433))).Matched);}
    [Fact] public async Task Raw_Service_Text_Without_Source_Port_Cannot_Assert_Role(){Assert.False(await Seen(port:50000));}
    [Fact] public async Task Private_And_Documentation_Destinations_Are_Excluded(){Assert.False(await Seen(dst:"10.61.0.20"));Assert.False(await Seen(dst:"203.0.113.8"));}
    [Fact] public async Task Alert_Redacts_Raw_Application_Info(){var r=await _rule.EvaluateAsync(AssetBatch061065Context.At(0,sourcePort:1433,flags:null,info:"SQL Server password=hidden"));var e=Assert.Single(r.Events);Assert.DoesNotContain("hidden",e.Description);Assert.DoesNotContain("hidden",e.Evidence);}
    [Fact] public async Task Cancellation_Stops_Evaluation(){using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(AssetBatch061065Context.At(0),c.Token));}
}
