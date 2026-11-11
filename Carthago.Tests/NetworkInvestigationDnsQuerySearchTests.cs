// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Contract authored before implementation; Windows execution deferred.
using Carthago.Models;
using Carthago.Views;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkInvestigationDnsQuerySearchTests
{
    [Fact]
    public void Dns_Question_Name_Is_Searchable_When_Address_And_Other_Text_Fields_Do_Not_Match()
    {
        var row = new TrafficRecord
        {
            Source = "192.0.2.20", Destination = "192.0.2.53", Protocol = "UDP",
            SourcePort = 50322, DestinationPort = 53,
            DnsQname = "Updates.Example.Test"
        };

        Assert.True(NetworkInvestigationPage.MatchesTrafficText(row, "updates.example.test"));
        Assert.True(NetworkInvestigationPage.MatchesTrafficText(row, "EXAMPLE.TEST"));
        Assert.False(NetworkInvestigationPage.MatchesTrafficText(row, "unrelated.example.test"));
    }

    [Fact]
    public void Existing_Host_And_Application_Text_Search_Still_Matches()
    {
        var row = new TrafficRecord
        {
            HttpHost = "web.example.test", Sni = "tls.example.test",
            ApplicationService = "https", ProcessName = "browser.exe"
        };

        Assert.True(NetworkInvestigationPage.MatchesTrafficText(row, "web.example.test"));
        Assert.True(NetworkInvestigationPage.MatchesTrafficText(row, "tls.example.test"));
        Assert.True(NetworkInvestigationPage.MatchesTrafficText(row, "HTTPS"));
        Assert.True(NetworkInvestigationPage.MatchesTrafficText(row, "browser.exe"));
    }

    [Fact]
    public void Unreviewed_Dns_Answer_And_Free_Text_Info_Are_Not_Introduced_As_Search_Sources()
    {
        var row = new TrafficRecord
        {
            Source = "192.0.2.20", Destination = "192.0.2.53",
            DnsQname = null, DnsAnswers = "sensitive-answer.example.test",
            Info = "internal-note.example.test"
        };

        Assert.False(NetworkInvestigationPage.MatchesTrafficText(row, "sensitive-answer.example.test"));
        Assert.False(NetworkInvestigationPage.MatchesTrafficText(row, "internal-note.example.test"));
        Assert.False(NetworkInvestigationPage.MatchesTrafficText(row, "unrelated.example.test"));
    }

    [Fact]
    public void Missing_Dns_Query_Metadata_Does_Not_Create_A_Hostname_Match()
    {
        var row = new TrafficRecord { Protocol = "DNS", DnsQname = "" };
        Assert.False(NetworkInvestigationPage.MatchesTrafficText(row, "updates.example.test"));
    }
}
