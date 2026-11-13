// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Models;
using Carthago.Services.ProtocolIntelligence;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableTrafficRecordTests
{
    [Fact]
    public void TrafficModelHasSinglePortableOwner()
    {
        var assembly = typeof(TrafficRecord).Assembly;
        Assert.Equal("Carthago.Core", assembly.GetName().Name);
        Assert.Same(assembly, typeof(DnsAddressObservationInspector).Assembly);
        Assert.DoesNotContain(assembly.GetReferencedAssemblies(), reference =>
            reference.Name is "Carthago" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
        Assert.NotEqual(Guid.Empty, new TrafficRecord().Id);
    }

    [Fact]
    public void PropertyChangeNotificationsAndAliasesArePreserved()
    {
        var record = new TrafficRecord();
        var changes = new List<string?>();
        record.PropertyChanged += (_, args) => changes.Add(args.PropertyName);
        record.Source = "192.0.2.10";
        record.DestinationPort = 443;
        record.Sni = "example.test";
        Assert.Equal("example.test", record.TlsSni);
        Assert.Equal(new[] { "Source", "DestinationPort", "Sni", "TlsSni" }, changes);
        changes.Clear();
        record.TlsSni = "second.test";
        Assert.Equal("second.test", record.Sni);
        Assert.Equal(new[] { "TlsSni", "Sni" }, changes);
    }

    [Fact]
    public void PublicTelemetrySurvivesJsonRoundTrip()
    {
        var record = new TrafficRecord
        {
            Source = "192.0.2.10", Destination = "198.51.100.20",
            SourcePort = 51000, DestinationPort = 443, IsTcp = true,
            L4Len = 42, Sni = "example.test"
        };
        var reopened = JsonSerializer.Deserialize<TrafficRecord>(JsonSerializer.Serialize(record))!;
        Assert.Equal(record.Id, reopened.Id);
        Assert.Equal(record.Source, reopened.Source);
        Assert.Equal(record.Destination, reopened.Destination);
        Assert.Equal(record.SourcePort, reopened.SourcePort);
        Assert.Equal(record.DestinationPort, reopened.DestinationPort);
        Assert.Equal(record.L4Len, reopened.L4Len);
        Assert.True(reopened.IsTcp);
        Assert.Equal(record.Sni, reopened.TlsSni);
    }

    [Fact]
    public void JsonCannotForgeCaptureOnlyEvidence()
    {
        const string json = """
            {"Source":"192.0.2.10","BacnetEventDisableRequestObserved":true,
             "DnsValidatedAQuestion":true,"DnsValidatedTransactionId":123,
             "HttpBasicDefaultCredentialObserved":true,"RedisRespConfigSetRequestObserved":true,
             "TftpInitialRequestOpcode":1,"Dnp3DisableUnsolicitedObserved":true,"ArpSenderMacMatchesFrame":true,
             "ModbusSingleRegisterWritePoint":42}
            """;
        var record = JsonSerializer.Deserialize<TrafficRecord>(json)!;
        Assert.Equal("192.0.2.10", record.Source);
        Assert.False(record.BacnetEventDisableRequestObserved);
        Assert.False(record.DnsValidatedAQuestion);
        Assert.Null(record.DnsValidatedTransactionId);
        Assert.False(record.HttpBasicDefaultCredentialObserved);
        Assert.False(record.RedisRespConfigSetRequestObserved);
        Assert.Null(record.TftpInitialRequestOpcode);
        Assert.False(record.Dnp3DisableUnsolicitedObserved);
        Assert.False(record.ArpSenderMacMatchesFrame);
        Assert.Null(record.ModbusSingleRegisterWritePoint);
    }

    [Fact]
    public void InternalEvidenceCanBeSetByTrustedProducerButNotRestoredFromJson()
    {
        var record = new TrafficRecord
        {
            BacnetEventDisableRequestObserved = true,
            DnsValidatedAQuestion = true,
            DnsValidatedTransactionId = 123,
            ArpSenderMacMatchesFrame = true,
            ModbusSingleRegisterWritePoint = 42
        };
        var json = JsonSerializer.Serialize(record);
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.GetProperty("BacnetEventDisableRequestObserved").GetBoolean());
        Assert.False(document.RootElement.TryGetProperty("ArpSenderMacMatchesFrame", out _));
        Assert.False(document.RootElement.TryGetProperty("ModbusSingleRegisterWritePoint", out _));
        var reopened = JsonSerializer.Deserialize<TrafficRecord>(json)!;
        Assert.False(reopened.BacnetEventDisableRequestObserved);
        Assert.False(reopened.DnsValidatedAQuestion);
        Assert.Null(reopened.DnsValidatedTransactionId);
    }

    [Fact]
    public void RichDnsObservationRemainsInternalAndNotSerialized()
    {
        var record = new TrafficRecord
        {
            DnsAddressObservation = new DnsAddressObservationInspector.Observation(
                123, "example.test", 1, true,
                new[] { new DnsAddressObservationInspector.AddressAnswer("192.0.2.1", 60) })
        };
        Assert.NotNull(record.DnsAddressObservation);
        using var json = JsonDocument.Parse(JsonSerializer.Serialize(record));
        Assert.False(json.RootElement.TryGetProperty("DnsAddressObservation", out _));
        Assert.Null(JsonSerializer.Deserialize<TrafficRecord>(json.RootElement.GetRawText())!.DnsAddressObservation);
    }
}
