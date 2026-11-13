// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Contracts;
using Carthago.Services.SessionFiles;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class InvestigationQueriesTests
{
    private static readonly string A = "00000000000000000000000000000001";
    private static readonly string B = "00000000000000000000000000000002";
    private static readonly DateTime Time = new(2026, 11, 13, 12, 0, 0, DateTimeKind.Utc);

    [Fact]
    public async Task AlertFiltersAndPaginationMatchStoredOrder()
    {
        await WithSession(s => s.AddRows("Alerts", new[] {
            new { EventId = A, TimestampUtc = Time, Severity = "High", SourceIp = "192.168.1.10" },
            new { EventId = B, TimestampUtc = Time, Severity = "Low", SourceIp = "192.168.1.10" } }),
            async path => {
                var page = await InvestigationQueries.ReadAsync(path, InvestigationKind.Alerts,
                    new(Severity: "HIGH", SourceIp: "192.168.1.10"), default);
                Assert.Equal(1, page.Total);
                Assert.Equal(A, Assert.Single(page.Rows).Id);
                Assert.Equal(Time, Assert.Single(page.Rows).ObservedUtc!.Value.UtcDateTime);
                Assert.Equal(B, Assert.Single((await InvestigationQueries.ReadAsync(path, InvestigationKind.Alerts,
                    new(Offset: 1, Limit: 1), default)).Rows).Id);
            });
    }

    [Fact]
    public async Task ShowUsesGuidIdentityAndNeverEmitsEvidence()
    {
        await WithSession(s => s.AddRows("Alerts", new[] { new { EventId = A, Severity = "High",
            RuleId = "R001", SourceIp = "not-an-ip", Description = "PRIVATE", Evidence = "SECRET",
            ProcessName = "PRIVATE-PROCESS", Protocol = "\u001b[31m" } }), async path => {
            var page = await InvestigationQueries.ReadAsync(path, InvestigationKind.Alerts,
                new(Id: Guid.Parse(A).ToString("D"), Limit: 1), default);
            var row = Assert.Single(page.Rows);
            Assert.Null(row.SourceIp);
            Assert.Null(row.Protocol);
            string json = JsonSerializer.Serialize(row);
            Assert.DoesNotContain("PRIVATE", json);
            Assert.DoesNotContain("SECRET", json);
        });
    }

    [Fact]
    public async Task IncidentProjectionUsesRealModelFields()
    {
        await WithSession(s => s.AddRows("Incidents", new[] { new { Id = A, IncidentId = A, UpdatedUtc = Time,
            PrimarySourceIp = "2001:db8::1", PrimaryRuleId = "R001", Severity = "critical",
            Status = "Investigating", RiskScore = 85, OccurrenceCount = 3, AnalystNote = "PRIVATE" } }),
            async path => {
                var row = Assert.Single((await InvestigationQueries.ReadAsync(path, InvestigationKind.Incidents,
                    new(SourceIp: "2001:0db8::1"), default)).Rows);
                Assert.Equal("investigating", row.Status);
                Assert.Equal(85, row.RiskScore);
                Assert.Equal(3, row.OccurrenceCount);
                Assert.DoesNotContain("PRIVATE", JsonSerializer.Serialize(row));
            });
    }

    [Fact]
    public async Task TrafficDisplayTimestampIsNotInventedUtc()
    {
        await WithSession(s => s.AddRows("Traffic", new[] { new { Id = A, Timestamp = "12:00:00",
            Source = "192.168.1.10", Destination = "8.8.8.8", Protocol = "UDP", Length = 64,
            DestinationPort = 53, Info = "PRIVATE" } }), async path => {
            var row = Assert.Single((await InvestigationQueries.ReadAsync(path, InvestigationKind.Events, new(), default)).Rows);
            Assert.Null(row.ObservedUtc);
            Assert.Equal(53, row.DestinationPort);
            Assert.Equal("udp", row.Protocol);
            Assert.DoesNotContain("PRIVATE", JsonSerializer.Serialize(row));
        });
    }

    [Fact]
    public async Task HostsDoNotExposeArbitraryLabels()
    {
        await WithSession(s => s.AddRows("Hosts", new[] { new { Host = "192.168.1.10", LastSeenUtc = Time },
            new { Host = "PRIVATE-HOST", LastSeenUtc = Time } }), async path => {
            var page = await InvestigationQueries.ReadAsync(path, InvestigationKind.Hosts, new(), default);
            Assert.Equal(1, page.Total);
            Assert.Equal(1, page.OmittedRows);
            Assert.Equal("192.168.1.10", Assert.Single(page.Rows).SourceIp);
        });
    }

    [Fact]
    public async Task DuplicateIdentityOutsideFilterFailsClosed()
    {
        await WithSession(s => s.AddRows("Alerts", new[] { new { EventId = A, Severity = "Low" },
            new { EventId = Guid.Parse(A).ToString("D"), Severity = "High" } }), async path =>
            await Assert.ThrowsAsync<InvalidDataException>(() => InvestigationQueries.ReadAsync(path,
                InvestigationKind.Alerts, new(Severity: "critical"), default)));
    }

    [Theory]
    [InlineData("alerts list x.csa --limit 101")]
    [InlineData("alerts list x.csa --severity unknown")]
    [InlineData("events list x.csa --severity high")]
    [InlineData("hosts list x.csa --source-ip secret")]
    [InlineData("events list x.csa --source-ip 127.1")]
    [InlineData("alerts list x.csa --limit 2 --limit 3")]
    [InlineData("incidents show x.csa invalid")]
    public void InvalidOptionsRejected(string args)
        => Assert.False(InvestigationCommand.TryParse(args.Split(' '), out _, out _, out _, out _));

    [Fact]
    public async Task MissingRecordUsesStderr()
    {
        await WithSession(_ => { }, async path => {
            using var output = new StringWriter();
            using var error = new StringWriter();
            int code = await CliApplication.RunAsync(new[] { "alerts", "show", path, A, "--json" }, output, error);
            Assert.Equal(3, code);
            Assert.Empty(output.ToString());
            Assert.Contains("record_not_found", error.ToString());
        });
    }

    private static async Task WithSession(Action<CarthagoSessionSnapshot> populate, Func<string, Task> test)
    {
        string path = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N") + ".csa");
        try { var snapshot = CarthagoSessionSnapshot.CreateEmpty(); populate(snapshot);
            await new CarthagoSessionArchiveService().SaveAsync(path, snapshot); await test(path); }
        finally { File.Delete(path); }
    }
}
