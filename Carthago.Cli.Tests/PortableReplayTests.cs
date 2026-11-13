// SPDX-License-Identifier: MIT
using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Carthago.Cli;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableReplayTests
{
    private static byte[] Frame(string path,string method="GET",string? ua=null)
    {
        var payload=Encoding.ASCII.GetBytes($"{method} {path} HTTP/1.1\r\nHost: example.test\r\n"+(ua is null?"":$"User-Agent: {ua}\r\n")+"\r\n");
        var b=new byte[40+payload.Length];
        b[0]=0x45;b[8]=64;b[9]=6;
        new byte[]{192,0,2,1,198,51,100,2}.CopyTo(b,12);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(2),(ushort)b.Length);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(20),51000);
        BinaryPrimitives.WriteUInt16BigEndian(b.AsSpan(22),7001);
        b[32]=0x50;b[33]=0x18;payload.CopyTo(b,40);return b;
    }
    private static byte[] Pcap(params (uint Seconds,byte[] Data,uint? Original)[] packets)
    {
        using var m=new MemoryStream();using var w=new BinaryWriter(m);
        w.Write(0xa1b2c3d4u);w.Write((ushort)2);w.Write((ushort)4);w.Write(0u);w.Write(0u);w.Write(65535u);w.Write(101u);
        foreach(var p in packets){w.Write(p.Seconds);w.Write(0u);w.Write((uint)p.Data.Length);w.Write(p.Original??(uint)p.Data.Length);w.Write(p.Data);}
        return m.ToArray();
    }
    private static byte[] Block(uint type,Action<BinaryWriter> body)
    {
        using var m=new MemoryStream();using var w=new BinaryWriter(m);body(w);
        var b=m.ToArray();using var all=new MemoryStream();using var a=new BinaryWriter(all);
        a.Write(type);a.Write((uint)(b.Length+12));a.Write(b);a.Write((uint)(b.Length+12));return all.ToArray();
    }
    private static byte[] Section()=>Block(0x0a0d0d0a,w=>{w.Write(0x1a2b3c4du);w.Write((ushort)1);w.Write((ushort)0);w.Write(-1L);});
    private static byte[] Interface()=>Block(1,w=>{w.Write((ushort)101);w.Write((ushort)0);w.Write(65535u);});
    private static byte[] Packet(uint id,ulong time,byte[] b)=>Block(6,w=>{
        w.Write(id);w.Write((uint)(time>>32));w.Write((uint)time);w.Write((uint)b.Length);w.Write((uint)b.Length);
        w.Write(b);w.Write(new byte[(4-b.Length%4)%4]);});
    private static async Task<(int Code,string Output,string Error)> Run(byte[] bytes,string ext,string ids="R589",int limit=50,CancellationToken token=default)
    {
        var path=Path.Combine(Path.GetTempPath(),Guid.NewGuid()+ext);
        try
        {
            await File.WriteAllBytesAsync(path,bytes);
            using var output=new StringWriter();using var error=new StringWriter();
            int code=await CliApplication.RunAsync(new[]{"pcap","detect",path,"--rules",ids,"--limit",limit.ToString(System.Globalization.CultureInfo.InvariantCulture),"--json"},output,error,token);
            return(code,output.ToString(),error.ToString());
        }
        finally{File.Delete(path);}
    }

    [Fact]
    public async Task ClassicReplayCountsMatchesSuppressionAndUnsupportedWithoutLeakingUri()
    {
        var hit=Frame("/config/keystore/test.jsp?secret=private");
        var bytes=Pcap((100,hit,null),(101,hit,null),(102,Frame("/other/test.jsp"),null),
            (700,hit,null),(701,hit,(uint)hit.Length+1),(702,new byte[]{0},null));
        var r=await Run(bytes,".pcap","R589,R1000",1);
        Assert.Equal(0,r.Code);Assert.Empty(r.Error);Assert.DoesNotContain("secret",r.Output);
        using var json=JsonDocument.Parse(r.Output);var root=json.RootElement;var replay=root.GetProperty("replay");
        Assert.Equal("not_assessed",root.GetProperty("detectionValidation").GetString());
        Assert.Equal(6,replay.GetProperty("packetsRead").GetInt32());
        Assert.Equal(4,replay.GetProperty("parsed").GetInt32());
        Assert.Equal(1,replay.GetProperty("rejected").GetInt32());
        Assert.Equal(1,replay.GetProperty("captureTruncated").GetInt32());
        Assert.Equal(2,replay.GetProperty("matchCount").GetInt32());
        Assert.Equal(1,replay.GetProperty("suppressedCount").GetInt32());
        Assert.True(replay.GetProperty("findingsTruncated").GetBoolean());
        Assert.Single(replay.GetProperty("findings").EnumerateArray());
        var rules=replay.GetProperty("rules");
        Assert.Equal(4,rules[0].GetProperty("evaluated").GetInt32());
        Assert.Equal("unsupported_detector",rules[1].GetProperty("status").GetString());
        Assert.Equal(0,rules[1].GetProperty("evaluated").GetInt32());
    }

    [Fact]
    public async Task NgInterfacesSectionsAndClockResetIsolateDetectorState()
    {
        var hit=Frame("/config/keystore/test.jsp");
        var bytes=new[]{Section(),Interface(),Interface(),Packet(0,2_000_000,hit),
            Packet(1,2_000_000,hit),Packet(0,3_000_000,hit),Packet(0,1_000_000,hit),
            Section(),Interface(),Packet(0,1_000_000,hit)}.SelectMany(x=>x).ToArray();
        var r=await Run(bytes,".pcapng");Assert.Equal(0,r.Code);
        using var json=JsonDocument.Parse(r.Output);var replay=json.RootElement.GetProperty("replay");
        Assert.Equal(4,replay.GetProperty("matchCount").GetInt32());
        Assert.Equal(1,replay.GetProperty("suppressedCount").GetInt32());
        Assert.Equal(1,replay.GetProperty("clockResets").GetInt32());
        var findings=replay.GetProperty("findings");
        Assert.Equal(1,findings[1].GetProperty("interfaceId").GetInt32());
        Assert.Equal(1,findings[3].GetProperty("section").GetInt32());
    }

    [Fact]
    public async Task SeparateRunsDoNotShareCooldownAndUnsupportedOnlyIsExplicit()
    {
        var bytes=Pcap((100,Frame("/config/keystore/test.jsp"),null));
        foreach(var ids in new[]{"R589","R589","R1000"})
        {
            var r=await Run(bytes,".pcap",ids);Assert.Equal(0,r.Code);
            using var json=JsonDocument.Parse(r.Output);var replay=json.RootElement.GetProperty("replay");
            Assert.Equal(ids=="R589"?1:0,replay.GetProperty("matchCount").GetInt32());
            Assert.Equal(ids=="R589"?"evaluated":"unsupported_detector",replay.GetProperty("rules")[0].GetProperty("status").GetString());
        }
    }

    [Fact]
    public async Task MalformedTailAndCancellationNeverEmitPartialSuccess()
    {
        var bytes=Pcap((100,Frame("/config/keystore/test.jsp"),null));
        var bad=await Run(bytes.Concat(new byte[]{1}).ToArray(),".pcap");
        Assert.Equal(3,bad.Code);Assert.Empty(bad.Output);
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        var stopped=await Run(bytes,".pcap",token:cancel.Token);
        Assert.Equal(130,stopped.Code);Assert.Empty(stopped.Output);
    }

    [Fact]
    public async Task TwoRulesHaveIndependentCountersAndCooldowns()
    {
        var wizard=Frame("/SetupWizard.aspx/next");
        var keystore=Frame("/config/keystore/test.jsp");
        var both=Frame("/SetupWizard.aspx/config/keystore/test.jsp");
        var bytes=Pcap((100,wizard,null),(101,keystore,null),(102,both,null),
            (700,wizard,null),(701,Frame("/other?x=/SetupWizard.aspx/next"),null));
        var r=await Run(bytes,".pcap","R589,R587,R1000",2);
        Assert.Equal(0,r.Code);
        using var json=JsonDocument.Parse(r.Output);
        var replay=json.RootElement.GetProperty("replay");
        Assert.Equal(3,replay.GetProperty("matchCount").GetInt32());
        Assert.Equal(2,replay.GetProperty("suppressedCount").GetInt32());
        Assert.True(replay.GetProperty("findingsTruncated").GetBoolean());
        var rules=replay.GetProperty("rules");
        Assert.Equal("R589",rules[0].GetProperty("ruleId").GetString());
        Assert.Equal(1,rules[0].GetProperty("matches").GetInt32());
        Assert.Equal(2,rules[1].GetProperty("matches").GetInt32());
        Assert.Equal(1,rules[0].GetProperty("suppressed").GetInt32());
        Assert.Equal(1,rules[1].GetProperty("suppressed").GetInt32());
        Assert.Equal(5,rules[0].GetProperty("evaluated").GetInt32());
        Assert.Equal(5,rules[1].GetProperty("evaluated").GetInt32());
        Assert.Equal("unsupported_detector",rules[2].GetProperty("status").GetString());
        Assert.Equal("R587",replay.GetProperty("findings")[0].GetProperty("ruleId").GetString());
        Assert.Equal("R589",replay.GetProperty("findings")[1].GetProperty("ruleId").GetString());
    }

    [Fact]
    public async Task OnePacketCanMatchBothRulesInSelectionOrder()
    {
        var r=await Run(Pcap((100,Frame("/SetupWizard.aspx/config/keystore/test.jsp"),null)),".pcap","R589,R587");
        Assert.Equal(0,r.Code);
        using var json=JsonDocument.Parse(r.Output);
        var findings=json.RootElement.GetProperty("replay").GetProperty("findings");
        Assert.Equal(2,findings.GetArrayLength());
        Assert.Equal("R589",findings[0].GetProperty("ruleId").GetString());
        Assert.Equal("R587",findings[1].GetProperty("ruleId").GetString());
    }

    [Fact]
    public async Task FivePortableRulesKeepIndependentCountsAcrossCapture()
    {
        var bytes=Pcap((100,Frame("/wp-content/plugins/wp2shell_test/file.php"),null),
            (101,Frame("/SetupWizard.aspx/next"),null),
            (102,Frame("/LogoImageHandler.ashx?clazz=example"),null),
            (103,Frame("/config/keystore/test.jsp"),null),
            (104,Frame("/?search=%00{.cmd.exe"),null),
            (105,Frame("/wp-content/plugins/wp2shell_test/file.php"),null),
            (106,Frame("/LogoImageHandler.ashx?class=example"),null));
        var r=await Run(bytes,".pcap","R590,R589,R588,R587,R586,R1000");
        Assert.Equal(0,r.Code);
        using var json=JsonDocument.Parse(r.Output);
        var replay=json.RootElement.GetProperty("replay");
        Assert.Equal(5,replay.GetProperty("matchCount").GetInt32());
        Assert.Equal(1,replay.GetProperty("suppressedCount").GetInt32());
        var rules=replay.GetProperty("rules");
        for(int i=0;i<5;i++)
        {
            Assert.Equal(7,rules[i].GetProperty("evaluated").GetInt32());
            Assert.Equal(1,rules[i].GetProperty("matches").GetInt32());
            Assert.Equal(i==4?1:0,rules[i].GetProperty("suppressed").GetInt32());
        }
        Assert.Equal("unsupported_detector",rules[5].GetProperty("status").GetString());
        Assert.Equal(new[]{"R586","R587","R588","R589","R590"},replay.GetProperty("findings")
            .EnumerateArray().Select(f=>f.GetProperty("ruleId").GetString()).ToArray());
        Assert.DoesNotContain("cmd.exe",r.Output);
    }

    [Theory]
    [InlineData("R589,R589")]
    [InlineData("R0589")]
    [InlineData("r589")]
    [InlineData("R589, R1000")]
    [InlineData("R589,")]
    public async Task InvalidRuleSelectionFailsBeforeFileAccess(string ids)
    {
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(2,await CliApplication.RunAsync(new[]{"pcap","detect","missing.pcap","--rules",ids,"--json"},output,error));
        Assert.Empty(output.ToString());
    }

    [Fact]
    public async Task NextFivePortableRulesReplayIndependently()
    {
        var bytes=Pcap((100,Frame("/ServletApi/../RestApi/LogonCustomization"),null),
            (101,Frame("/test.html?dwn=example&fn=sample"),null),
            (102,Frame("/?doAs=`example`"),null),
            (103,Frame("/rest/api/latest/projects/test?prefix=%00--exec"),null),
            (104,Frame("/public/plugins/graph/../../../../example"),null),
            (105,Frame("/ServletApi/../RestApi/LogonCustomization"),null),(106,Frame("/public/plugins/graph/../../../example"),null));
        var r=await Run(bytes,".pcap","R591,R592,R593,R594,R595,R1000");
        Assert.Equal(0,r.Code);
        using var json=JsonDocument.Parse(r.Output);var replay=json.RootElement.GetProperty("replay");
        Assert.Equal(5,replay.GetProperty("matchCount").GetInt32());
        Assert.Equal(1,replay.GetProperty("suppressedCount").GetInt32());
        Assert.Equal(new[]{"R591","R592","R593","R594","R595"},replay.GetProperty("findings").EnumerateArray()
            .Select(f=>f.GetProperty("ruleId").GetString()).ToArray());
        Assert.DoesNotContain("%00--exec",r.Output);
        Assert.Equal("unsupported_detector",replay.GetProperty("rules")[5].GetProperty("status").GetString());
    }

    [Fact]
    public async Task HeaderAndPostRulesReplayWithIndependentCounters()
    {
        var bytes=Pcap((100,Frame("/cgi-bin/jarrewrite.sh", "GET", "() { example"),null),
            (101,Frame("/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini%00"),null),
            (102,Frame("/?file=C:/Users/example"),null),
            (103,Frame("/apply_abstract.cgi?file=..%2fexample"),null),
            (104,Frame("/owa/auth/Current/themes/resources/example", "POST"),null),
            (105,Frame("/cgi-bin/jarrewrite.sh","GET","() { example"),null),
            (106,Frame("/cgi-bin/jarrewrite.sh"),null),(107,Frame("/owa/auth/Current/themes/resources/example"),null));
        var r=await Run(bytes,".pcap","R596,R597,R598,R599,R600,R1000");
        Assert.Equal(0,r.Code);
        using var json=JsonDocument.Parse(r.Output);var replay=json.RootElement.GetProperty("replay");
        Assert.Equal(5,replay.GetProperty("matchCount").GetInt32());
        Assert.Equal(1,replay.GetProperty("suppressedCount").GetInt32());
        Assert.Equal(new[]{"R596","R597","R598","R599","R600"},replay.GetProperty("findings").EnumerateArray()
            .Select(f=>f.GetProperty("ruleId").GetString()).ToArray());
        Assert.DoesNotContain("() { example",r.Output);
        Assert.DoesNotContain("C:/Users",r.Output);
        Assert.Equal("POST",replay.GetProperty("findings")[4].GetProperty("method").GetString());
        Assert.Equal("unsupported_detector",replay.GetProperty("rules")[5].GetProperty("status").GetString());
    }
}
