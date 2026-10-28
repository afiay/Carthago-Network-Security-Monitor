// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml.Linq;
using Carthago.Services.TrustedAudit;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class WinRmSecurityAuditIntakeTests
{
    private static readonly XNamespace Ns =
        "http://schemas.microsoft.com/win/2004/08/events/event";
    private static readonly DateTimeOffset Start =
        new(2026, 10, 28, 23, 0, 0, TimeSpan.Zero);
    private static string Encoded() =>
        Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Output 42"));

    private static Dictionary<string, string> ProcessFields() => new(StringComparer.Ordinal)
    {
        ["NewProcessName"] = @"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        ["ParentProcessName"] = @"C:\Windows\System32\wsmprovhost.exe",
        ["CommandLine"] = "powershell.exe -EncodedCommand " + Encoded(),
        ["NewProcessId"] = "0x2222",
        ["ProcessId"] = "0x1111",
        ["SubjectLogonId"] = "0x12345",
        ["TargetLogonId"] = "0x0"
    };

    private static Dictionary<string, string> NetworkLogonFields() => new(StringComparer.Ordinal)
    {
        ["LogonType"] = "3",
        ["TargetLogonId"] = "0x12345",
        ["IpAddress"] = "10.30.40.50",
        ["WorkstationName"] = "WINCLIENT"
    };

    private static string Xml(int id, long recordId, DateTimeOffset timestamp,
        Dictionary<string, string> fields, string machine = "CARTHAGE",
        string channel = "Security",
        string provider = "Microsoft-Windows-Security-Auditing",
        string? duplicateField = null)
    {
        var data = fields.Select(field => new XElement(Ns + "Data",
            new XAttribute("Name", field.Key), field.Value)).ToList();
        if (duplicateField != null)
            data.Add(new XElement(Ns + "Data", new XAttribute("Name", duplicateField), "forged"));
        var document = new XDocument(new XElement(Ns + "Event",
            new XElement(Ns + "System",
                new XElement(Ns + "Provider", new XAttribute("Name", provider)),
                new XElement(Ns + "EventID", id),
                new XElement(Ns + "TimeCreated", new XAttribute("SystemTime",
                    timestamp.ToUniversalTime().ToString("O"))),
                new XElement(Ns + "EventRecordID", recordId),
                new XElement(Ns + "Channel", channel),
                new XElement(Ns + "Computer", machine)),
            new XElement(Ns + "EventData", data)));
        return document.ToString(SaveOptions.DisableFormatting);
    }

    private static WinRmSecurityAuditObservation Inspect(int id, long recordId,
        DateTimeOffset when, Dictionary<string, string> fields)
    {
        Assert.True(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(id, recordId, when, fields), out var result, out var reason), reason);
        Assert.NotNull(result);
        Assert.False(result.FromLocalSecurityLog);
        return result;
    }

    [Fact]
    public void Untrusted_4688_Candidate_Contains_No_Raw_Encoded_Command()
    {
        var fields = ProcessFields();
        var process = Inspect(4688, 101, Start.AddMinutes(1), fields);
        Assert.Equal(WinRmSecurityObservationKind.EncodedPowerShellProcessCreation, process.Kind);
        Assert.Equal((uint)0x2222, process.ProcessId);
        Assert.Equal((uint)0x1111, process.ParentProcessId);
        Assert.Equal((ulong)0x12345, process.LogonId);
        Assert.DoesNotContain("CommandLine", string.Join(",",
            typeof(WinRmSecurityAuditObservation).GetProperties().Select(p => p.Name)));
        Assert.DoesNotContain(Encoded(), process.ToString() ?? "", StringComparison.Ordinal);
    }

    [Fact]
    public void Network_Logon_And_Process_Produce_Only_Unsigned_Candidate()
    {
        var login = Inspect(4624, 100, Start, NetworkLogonFields());
        var process = Inspect(4688, 101, Start.AddMinutes(1), ProcessFields());
        Assert.True(WinRmSecurityAuditIntake.TryCorrelateCandidate(
            login, process, out var candidate, out var reason));
        Assert.Equal("UNATTESTED_CANDIDATE_ONLY", reason);
        Assert.NotNull(candidate);
        Assert.Equal("10.30.40.50", candidate.RemoteIp);
        Assert.Equal((ulong)0x12345, candidate.LogonId);
        Assert.False(candidate.FromLocalSecurityLog);
        Assert.DoesNotContain("Claim", string.Join(",",
            typeof(WinRmAuditCandidate).GetProperties().Select(p => p.Name)));
        Assert.DoesNotContain(Encoded(), candidate.ToString() ?? "", StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("SubjectLogonId", "0x0")]
    [InlineData("NewProcessId", "0x0")]
    [InlineData("NewProcessName", @"C:\Temp\fakepowershell.exe")]
    [InlineData("ParentProcessName", @"C:\Temp\fakewsmprovhost.exe")]
    [InlineData("ParentProcessName", "wsmprovhost.exe")]
    [InlineData("CommandLine", "powershell.exe -NoProfile")]
    [InlineData("CommandLine", "powershell.exe -EncodedCommand NOT_BASE64")]
    public void Spoofed_Or_Incomplete_4688_Fields_Do_Not_Create_Candidate(
        string key, string replacement)
    {
        var fields = ProcessFields();
        fields[key] = replacement;
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4688, 101, Start.AddMinutes(1), fields), out var eventResult, out _));
        Assert.Null(eventResult);
    }

    [Theory]
    [InlineData("NewProcessName", @"C:\Temp\powershell.exe")]
    [InlineData("NewProcessName", @"C:\Users\Public\powershell.exe")]
    [InlineData("NewProcessName", @"C:\Windows\Temp\powershell.exe")]
    [InlineData("NewProcessName", @"C:\Windows\System32\powershell.exe")]
    [InlineData("NewProcessName", @"C:\Windows\System32\WindowsPowerShell\v1.0\pwsh.exe")]
    [InlineData("ParentProcessName", @"C:\Temp\wsmprovhost.exe")]
    [InlineData("ParentProcessName", @"C:\Users\Public\wsmprovhost.exe")]
    [InlineData("ParentProcessName", @"C:\Windows\Temp\wsmprovhost.exe")]
    [InlineData("ParentProcessName", @"C:\Windows\System32\not-wsmprovhost.exe")]
    public void Lookalike_Executable_Locations_Are_Not_Trusted_As_Candidates(
        string field, string replacement)
    {
        var fields = ProcessFields();
        fields[field] = replacement;
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4688, 101, Start.AddMinutes(1), fields),
            out var result, out _));
        Assert.Null(result);
    }

    [Fact]
    public void Installed_PowerShell_7_And_Expected_System_Parent_Remain_Candidates()
    {
        var fields = ProcessFields();
        var programFiles = Environment.GetEnvironmentVariable("ProgramFiles")
            ?? @"C:\Program Files";
        fields["NewProcessName"] = programFiles.TrimEnd('\\')
            + @"\PowerShell\7\pwsh.exe";
        fields["CommandLine"] = "pwsh.exe -EncodedCommand " + Encoded();
        var observation = Inspect(4688, 101, Start.AddMinutes(1), fields);
        Assert.Equal(WinRmSecurityObservationKind.EncodedPowerShellProcessCreation,
            observation.Kind);
        Assert.False(observation.FromLocalSecurityLog);
    }

    [Theory]
    [InlineData("cmd.exe")]
    [InlineData(@"C:\Windows\System32\cmd.exe")]
    [InlineData("rundll32.exe")]
    [InlineData(@"C:\Temp\powershell.exe")]
    [InlineData("pwsh.exe")]
    [InlineData("powershell.exe-extra")]
    [InlineData("\"powershell.exe\"extra")]
    public void Unrelated_Command_Launcher_Cannot_Borrow_EncodedCommand_Flag(
        string launcher)
    {
        var fields = ProcessFields();
        fields["CommandLine"] = launcher + " -EncodedCommand " + Encoded();
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4688, 101, Start.AddMinutes(1), fields),
            out var result, out _));
        Assert.Null(result);
    }

    [Fact]
    public void Quoted_Exact_PowerShell_Image_In_CommandLine_Remains_Candidate()
    {
        var fields = ProcessFields();
        fields["CommandLine"] = "\"" + fields["NewProcessName"]
            + "\" -NoProfile -EncodedCommand " + Encoded();
        var observation = Inspect(4688, 101, Start.AddMinutes(1), fields);
        Assert.Equal((uint)0x2222, observation.ProcessId);
        Assert.False(observation.FromLocalSecurityLog);
    }

    [Theory]
    [InlineData("LogonType", "2")]
    [InlineData("TargetLogonId", "0x0")]
    [InlineData("IpAddress", "127.0.0.1")]
    [InlineData("IpAddress", "::1")]
    [InlineData("IpAddress", "::ffff:127.0.0.1")]
    [InlineData("IpAddress", "-")]
    public void Local_Interactive_Or_Unattributed_Logon_Does_Not_Qualify(
        string field, string value)
    {
        var fields = NetworkLogonFields();
        fields[field] = value;
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4624, 100, Start, fields), out _, out _));
    }

    [Theory]
    [InlineData("Security", "Forged-Provider")]
    [InlineData("Application", "Microsoft-Windows-Security-Auditing")]
    public void Wrong_Channel_Or_Provider_Cannot_Impersonate_Security_Event(
        string channel, string provider)
    {
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4688, 101, Start.AddMinutes(1), ProcessFields(),
                channel: channel, provider: provider), out _, out _));
    }

    [Theory]
    [InlineData("wrong-machine")]
    [InlineData("wrong-logon")]
    [InlineData("wrong-order")]
    [InlineData("large-time-gap")]
    [InlineData("process-before-logon")]
    public void Unrelated_4624_And_4688_Are_Never_Correlated(string mismatch)
    {
        var logon = NetworkLogonFields();
        var process = ProcessFields();
        var loginComputer = mismatch == "wrong-machine" ? "OTHERHOST" : "CARTHAGE";
        if (mismatch == "wrong-logon")
            logon["TargetLogonId"] = "0x99999";
        var firstTime = mismatch == "process-before-logon"
            ? Start.AddMinutes(2) : Start;
        var nextTime = mismatch == "large-time-gap"
            ? Start.AddMinutes(20) : Start.AddMinutes(1);
        var loginRecord = mismatch == "wrong-order" ? 105 : 100;
        Assert.True(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4624, loginRecord, firstTime, logon, loginComputer),
            out var login, out _));
        var spawned = Inspect(4688, 101, nextTime, process);
        Assert.False(WinRmSecurityAuditIntake.TryCorrelateCandidate(
            login, spawned, out var association, out _));
        Assert.Null(association);
    }

    [Fact]
    public async System.Threading.Tasks.Task Correlated_Untrusted_Audit_Still_Does_Not_Satisfy_R343()
    {
        var login = Inspect(4624, 100, Start, NetworkLogonFields());
        var process = Inspect(4688, 101, Start.AddMinutes(1), ProcessFields());
        Assert.True(WinRmSecurityAuditIntake.TryCorrelateCandidate(
            login, process, out var candidate, out _));
        Assert.NotNull(candidate);
        Assert.False(candidate.FromLocalSecurityLog);

        var packet = new TrafficRecord
        {
            Source = candidate.RemoteIp,
            Destination = "10.30.40.99",
            SourcePort = 51111,
            DestinationPort = 5985,
            IsTcp = true,
            Protocol = "TCP",
            ApplicationProtocol = "WinRM",
            ProcessName = "powershell.exe",
            Info = "remoting encoded command observed"
        };
        var evaluation = await new R343_PowerShellRemotingEncodedCommandRule()
            .EvaluateAsync(new RuleEvaluationContext(
                packet, Sensitivity.Balanced, Start.UtcDateTime));
        Assert.False(evaluation.Matched);
        Assert.Empty(evaluation.Events);
    }

    [Fact]
    public void Duplicate_Data_Field_And_Dtd_Are_Rejected()
    {
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4688, 101, Start.AddMinutes(1), ProcessFields(), duplicateField: "NewProcessId"),
            out _, out _));
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            "<!DOCTYPE Event [<!ENTITY leak SYSTEM 'file:///C:/secret'>]>" +
            Xml(4688, 101, Start.AddMinutes(1), ProcessFields()), out _, out _));
    }

    [Fact]
    public void Wrong_Event_Id_And_Missing_Event_Data_Are_Rejected()
    {
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4104, 101, Start.AddMinutes(1), ProcessFields()), out _, out _));
        Assert.False(WinRmSecurityAuditIntake.TryInspectUntrustedXml(
            Xml(4688, 101, Start.AddMinutes(1), new Dictionary<string, string>()),
            out _, out _));
    }

    [Fact]
    public void Local_Reader_Refuses_An_Unbounded_Request_Without_Querying_Security()
    {
        var reader = new WinRmLocalSecurityAuditReader();
        Assert.False(reader.TryReadRecent(out var results, out var reason, maxRecords: 5000));
        Assert.Empty(results);
        Assert.Equal("INVALID_READ_LIMIT", reason);
    }
}
