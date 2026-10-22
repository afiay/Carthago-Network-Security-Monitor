using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Tests;

public sealed class ApprovedAssetRegistryTests
{
    [Fact]
    public void Approved_Mqtt_Broker_Shadows_R113()
    {
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions
            {
                MqttBrokers = { "mqtt.approved.local" }
            }
        });
        var evt = CreateEvent("R113", "10.40.0.10", "198.51.100.20", 1883, "MQTT broker connection to unapproved host", host: "mqtt.approved.local", protocol: "MQTT");
        var decision = RuleTuningCatalog.Resolve("IoTHeavy", Descriptor("R113"), evt, CreateRecord(evt), registry);

        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
        Assert.Contains(decision.ReasonDetails, detail => detail.Contains("Approved MQTT broker", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Unapproved_Mqtt_Broker_Alerts_In_IotHeavy()
    {
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions());
        var evt = CreateEvent("R113", "10.40.0.10", "198.51.100.20", 1883, "MQTT broker connection to unapproved host", host: "bad-mqtt.example", protocol: "MQTT");
        var decision = RuleTuningCatalog.Resolve("IoTHeavy", Descriptor("R113"), evt, CreateRecord(evt), registry);

        Assert.Equal(RuleMode.Alert, decision.EffectiveMode);
    }

    [Fact]
    public void Approved_Ot_Controller_Prevents_False_Positive()
    {
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions
            {
                OtSegments = { "10.20.0.0/24" },
                BacnetControllers = { "10.20.0.11" }
            }
        });
        var evt = CreateEvent("R485", "10.20.0.20", "10.20.0.11", 47808, "BACnet write property", host: "10.20.0.11", protocol: "BACnet");
        var decision = RuleTuningCatalog.Resolve("OTSegment", Descriptor("R485"), evt, CreateRecord(evt), registry);

        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
    }

    [Fact]
    public void Unapproved_Modbus_Write_Alerts_In_OtSegment()
    {
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions
            {
                OtSegments = { "10.20.0.0/24" },
                ModbusControllers = { "10.20.0.10" }
            }
        });
        var evt = CreateEvent("R240", "10.30.0.20", "10.30.0.40", 502, "write multiple registers", host: "10.30.0.40", protocol: "Modbus");
        var decision = RuleTuningCatalog.Resolve("OTSegment", Descriptor("R240"), evt, CreateRecord(evt), registry);

        Assert.Equal(RuleMode.Alert, decision.EffectiveMode);
    }

    [Fact]
    public void Allowlist_Decision_Is_Recordable_As_Evidence_And_Does_Not_Delete_Detection()
    {
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions
            {
                MqttBrokers = { "mqtt.approved.local" }
            }
        });
        var evt = CreateEvent("R113", "10.40.0.10", "198.51.100.20", 1883, "MQTT broker connection to unapproved host", host: "mqtt.approved.local", protocol: "MQTT");
        var decision = RuleTuningCatalog.Resolve("IoTHeavy", Descriptor("R113"), evt, CreateRecord(evt), registry);

        foreach (var detail in decision.ReasonDetails)
            EvidenceBuilder.AppendEvidence(evt, "allowlist.reason", detail, "approved-assets");

        Assert.Contains("Approved MQTT broker", evt.Evidence, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("R113", evt.RuleId);
        Assert.False(string.IsNullOrWhiteSpace(evt.Description));
    }

    private static RuleDescriptor Descriptor(string ruleId)
        => RuleCatalog.Find(ruleId) ?? throw new InvalidOperationException($"Missing descriptor for {ruleId}.");

    private static DetectionEvent CreateEvent(string ruleId, string sourceIp, string destinationIp, int destinationPort, string description, string host, string protocol)
        => new()
        {
            RuleId = ruleId,
            RuleName = Descriptor(ruleId).Name,
            ConfidenceScore = 0.96,
            Description = description,
            Summary = description,
            Evidence = description,
            TimestampUtc = new DateTime(2026, 4, 28, 12, 0, 0, DateTimeKind.Utc),
            SourceIp = sourceIp,
            DestinationIp = destinationIp,
            DestinationHost = host,
            DestinationPort = destinationPort,
            Protocol = protocol,
            Severity = SeverityLevel.High
        };

    private static TrafficRecord CreateRecord(DetectionEvent evt)
        => new()
        {
            Source = evt.SourceIp,
            Destination = evt.DestinationIp,
            DestinationPort = evt.DestinationPort,
            Protocol = evt.Protocol,
            Info = evt.Description,
            HttpHost = evt.DestinationHost,
            HttpUri = evt.Description,
            ApplicationProtocol = evt.Protocol,
            ApplicationService = evt.Protocol,
            IsTcp = true
        };
}
