// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R168AdvancedAccuracyBatchTests
{
    [Fact] public async Task Database_Backup_Archive_Is_Observable()
    {
        Assert.True((await new R168_BackupArchiveDownloadProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/db_backup_2026.sql.gz")))).Matched);
    }
    [Fact] public async Task Ordinary_Report_Zip_Is_Benign()
    {
        Assert.False((await new R168_BackupArchiveDownloadProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/downloads/report.zip")))).Matched);
    }
    [Fact] public async Task Database_Word_In_NonArchive_Is_Not_Probe()
    {
        Assert.False((await new R168_BackupArchiveDownloadProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/docs/database-guide.html")))).Matched);
    }
    [Fact] public async Task Incidental_Db_Substring_In_Archive_Is_Not_Backup()
    {
        Assert.False((await new R168_BackupArchiveDownloadProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/downloads/adbdriver.zip")))).Matched);
    }
    [Fact] public async Task Udp_Transport_Contradiction_Is_Rejected()
    {
        var r=NetworkBatch166175Context.Http("/db_backup.sql.gz");r.IsTcp=false;r.IsUdp=true;Assert.False((await new R168_BackupArchiveDownloadProbeRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Packet_Cannot_Match_Twice()
    {
        var rule=new R168_BackupArchiveDownloadProbeRule();var r=NetworkBatch166175Context.Http("/db_backup.sql.gz");Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task Older_Packet_Cannot_Rewind_Window()
    {
        var rule=new R168_BackupArchiveDownloadProbeRule();Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/db_backup.sql.gz"),20))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/db_backup.sql.gz"),19))).Matched);
    }
    [Fact] public async Task Archive_Name_And_Query_Token_Are_Not_Emitted()
    {
        var r=NetworkBatch166175Context.Http("/db_backup_SECRET168.sql.gz?token=HIDDEN168");var x=await new R168_BackupArchiveDownloadProbeRule().EvaluateAsync(NetworkBatch166175Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET168",StringComparison.Ordinal)||i.Value.Contains("HIDDEN168",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R168_BackupArchiveDownloadProbeRule().PrecisionProfile;
        Assert.Equal(72,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
