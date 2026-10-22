using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.IotOt;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class IotOtPrecisionRuleTests
{
    public static IEnumerable<object[]> PrecisionIotRules()
    {
        yield return new object[] { new R113_MQTTBrokerConnectionToUnapprovedHostRule() };
        yield return new object[] { new R114_MQTTTopicEnumerationRule() };
        yield return new object[] { new R115_MQTTHighFrequencyPublishBurstRule() };
        yield return new object[] { new R116_UPnPExposureDiscoveryAbuseRule() };
        yield return new object[] { new R117_TelnetLoginAttemptToIoTDeviceRule() };
        yield return new object[] { new R118_DefaultCredentialIoTAttemptRule() };
        yield return new object[] { new R119_CameraNVRExternalBeaconRule() };
        yield return new object[] { new R120_ModbusTrafficOutsideApprovedSegmentRule() };
        yield return new object[] { new R121_BACnetDiscoveryFromNonAdminHostRule() };
        yield return new object[] { new R122_CoAPZigbeeGatewaySuspiciousEgressRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionIotRules))]
    public async Task Precision_iot_rules_return_no_match_without_ot_context(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.40.0.10",
            Destination = "10.40.0.20",
            DestinationPort = 443,
            Protocol = "TCP",
            IsTcp = true,
            Length = 512
        }));

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Theory]
    [MemberData(nameof(PrecisionIotRules))]
    public async Task Precision_iot_rules_return_no_match_for_anytext_only_input(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.40.0.11",
            Destination = "203.0.113.11",
            DestinationPort = 443,
            Protocol = "TCP",
            IsTcp = true,
            Info = "mqtt zigbee bacnet modbus telnet camera who-is upnp",
            Length = 1024
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R113_matches_external_public_mqtt_broker()
    {
        var rule = new R113_MQTTBrokerConnectionToUnapprovedHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.10",
            destination: "198.51.100.10",
            destinationPort: 1883,
            protocol: "MQTT",
            service: "MQTT",
            host: "broker.hivemq.com",
            info: "mqtt connect clientid=sensor-01",
            process: "gatewayd.exe")));

        var evt = AssertSingleEvent(result, "R113", SeverityLevel.High, 0.76);
        AssertEvidence(evt, "iot.protocolFamily", "iot.host", "matched_conditions");
    }

    [Fact]
    public async Task R113_ignores_internal_local_mqtt_broker()
    {
        var rule = new R113_MQTTBrokerConnectionToUnapprovedHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.11",
            destination: "10.40.1.20",
            destinationPort: 1883,
            protocol: "MQTT",
            service: "MQTT",
            host: "mqtt.approved.local",
            info: "mqtt connect clientid=sensor-02",
            process: "gatewayd.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R114_matches_wildcard_mqtt_subscription()
    {
        var rule = new R114_MQTTTopicEnumerationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.20",
            destination: "10.40.1.30",
            destinationPort: 1883,
            protocol: "MQTT",
            service: "MQTT",
            info: "subscribe topic=building/#",
            process: "python.exe")));

        var evt = AssertSingleEvent(result, "R114", SeverityLevel.High, 0.58);
        AssertEvidence(evt, "mqtt.topic", "matched_conditions");
    }

    [Fact]
    public async Task R114_ignores_publish_only_mqtt_traffic()
    {
        var rule = new R114_MQTTTopicEnumerationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.21",
            destination: "10.40.1.31",
            destinationPort: 1883,
            protocol: "MQTT",
            service: "MQTT",
            info: "publish topic=building/temp",
            process: "sensor.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R115_matches_external_mqtt_publish_burst()
    {
        var rule = new R115_MQTTHighFrequencyPublishBurstRule();
        var baseTime = new DateTime(2026, 4, 29, 10, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 90; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
                source: "10.40.1.30",
                destination: "198.51.100.30",
                destinationPort: 1883,
                protocol: "MQTT",
                service: "MQTT",
                host: "broker.hivemq.com",
                info: $"publish topic=device/{index % 12}",
                process: "python.exe"), baseTime.AddMilliseconds(index * 500)));
        }

        var evt = AssertSingleEvent(last!, "R115", SeverityLevel.High, 0.70);
        AssertEvidence(evt, "count", "mqtt.distinctTopics", "matched_conditions");
    }

    [Fact]
    public async Task R115_ignores_moderate_internal_publish_rate()
    {
        var rule = new R115_MQTTHighFrequencyPublishBurstRule();
        var baseTime = new DateTime(2026, 4, 29, 10, 5, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 90; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
                source: "10.40.1.31",
                destination: "10.40.1.40",
                destinationPort: 1883,
                protocol: "MQTT",
                service: "MQTT",
                host: "mqtt.internal.local",
                info: "publish topic=device/temp",
                process: "sensor.exe"), baseTime.AddMilliseconds(index * 500)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R116_matches_external_upnp_discovery()
    {
        var rule = new R116_UPnPExposureDiscoveryAbuseRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.40",
            destination: "198.51.100.40",
            destinationPort: 1900,
            protocol: "UDP",
            service: "SSDP",
            info: "M-SEARCH * HTTP/1.1 ssdp:discover",
            isUdp: true,
            process: "svchost.exe")));

        var evt = AssertSingleEvent(result, "R116", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R116_ignores_single_local_upnp_probe()
    {
        var rule = new R116_UPnPExposureDiscoveryAbuseRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.41",
            destination: "239.255.255.250",
            destinationPort: 1900,
            protocol: "UDP",
            service: "SSDP",
            info: "M-SEARCH * HTTP/1.1 ssdp:discover",
            isUdp: true,
            process: "smarttv.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R117_matches_telnet_login_to_device()
    {
        var rule = new R117_TelnetLoginAttemptToIoTDeviceRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.50",
            destination: "10.40.1.60",
            destinationPort: 23,
            protocol: "TCP",
            service: "Telnet",
            info: "camera telnet login: admin password:",
            process: "putty.exe")));

        var evt = AssertSingleEvent(result, "R117", SeverityLevel.High, 0.68);
        AssertEvidence(evt, "network.destinationPort", "matched_conditions");
    }

    [Fact]
    public async Task R117_ignores_bare_port23_connection_without_auth()
    {
        var rule = new R117_TelnetLoginAttemptToIoTDeviceRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.51",
            destination: "10.40.1.61",
            destinationPort: 23,
            protocol: "TCP",
            service: "Telnet",
            info: "telnet session opened",
            process: "putty.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R118_matches_default_credential_attempt_to_device()
    {
        var rule = new R118_DefaultCredentialIoTAttemptRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.60",
            destination: "10.40.1.70",
            destinationPort: 8080,
            protocol: "HTTP",
            service: "HTTP",
            host: "camera.internal.local",
            info: "camera login admin:admin Authorization: Basic",
            process: "curl.exe")));

        var evt = AssertSingleEvent(result, "R118", SeverityLevel.Critical, 0.76);
        AssertEvidence(evt, "matched_conditions", "iot.protocolFamily");
    }

    [Fact]
    public async Task R118_ignores_unrelated_default_credential_string_without_device_context()
    {
        var rule = new R118_DefaultCredentialIoTAttemptRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.61",
            destination: "10.40.1.71",
            destinationPort: 443,
            protocol: "HTTP",
            service: "HTTP",
            info: "docs mention admin:admin in training material",
            process: "chrome.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R119_matches_repeated_camera_external_beacon()
    {
        var rule = new R119_CameraNVRExternalBeaconRule();
        var baseTime = new DateTime(2026, 4, 29, 11, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 5; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
                source: "10.40.1.70",
                destination: "198.51.100.70",
                destinationPort: 443,
                protocol: "TCP",
                service: "HTTPS",
                info: "camera onvif heartbeat",
                process: "camera.exe"), baseTime.AddMinutes(index * 2)));
        }

        var evt = AssertSingleEvent(last!, "R119", SeverityLevel.High, 0.70);
        AssertEvidence(evt, "count", "window_seconds", "matched_conditions");
    }

    [Fact]
    public async Task R119_ignores_one_off_camera_external_hit()
    {
        var rule = new R119_CameraNVRExternalBeaconRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.71",
            destination: "198.51.100.71",
            destinationPort: 443,
            protocol: "TCP",
            service: "HTTPS",
            info: "camera firmware check",
            process: "camera.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R120_matches_modbus_cross_segment_write()
    {
        var rule = new R120_ModbusTrafficOutsideApprovedSegmentRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.20.0.10",
            destination: "10.30.0.20",
            destinationPort: 502,
            protocol: "Modbus",
            service: "Modbus",
            info: "modbus write multiple registers function 16",
            process: "plc.exe")));

        var evt = AssertSingleEvent(result, "R120", SeverityLevel.Critical, 0.80);
        AssertEvidence(evt, "matched_conditions", "network.destinationPort");
    }

    [Fact]
    public async Task R120_ignores_same_subnet_modbus_read()
    {
        var rule = new R120_ModbusTrafficOutsideApprovedSegmentRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.20.0.10",
            destination: "10.20.0.20",
            destinationPort: 502,
            protocol: "Modbus",
            service: "Modbus",
            info: "modbus read holding register function 3",
            process: "plc.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R121_matches_bacnet_discovery_from_non_admin_source()
    {
        var rule = new R121_BACnetDiscoveryFromNonAdminHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.80",
            destination: "255.255.255.255",
            destinationPort: 47808,
            protocol: "BACnet",
            service: "BACnet",
            info: "bacnet who-is broadcast",
            process: "python.exe",
            isUdp: true)));

        var evt = AssertSingleEvent(result, "R121", SeverityLevel.High, 0.72);
        AssertEvidence(evt, "matched_conditions", "network.destinationPort");
    }

    [Fact]
    public async Task R121_ignores_admin_like_bacnet_discovery()
    {
        var rule = new R121_BACnetDiscoveryFromNonAdminHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.81",
            destination: "255.255.255.255",
            destinationPort: 47808,
            protocol: "BACnet",
            service: "BACnet",
            info: "bacnet who-is broadcast",
            process: "niagara.exe",
            isUdp: true)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R122_matches_repeated_zigbee_gateway_external_egress()
    {
        var rule = new R122_CoAPZigbeeGatewaySuspiciousEgressRule();
        var baseTime = new DateTime(2026, 4, 29, 11, 30, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
                source: "10.40.1.90",
                destination: "198.51.100.90",
                destinationPort: 443,
                protocol: "TCP",
                service: "HTTPS",
                info: "zigbee2mqtt gateway cloud sync",
                process: "gatewayd.exe"), baseTime.AddMinutes(index)));
        }

        var evt = AssertSingleEvent(last!, "R122", SeverityLevel.High, 0.70);
        AssertEvidence(evt, "count", "matched_conditions", "window_seconds");
    }

    [Fact]
    public async Task R122_ignores_internal_coap_traffic()
    {
        var rule = new R122_CoAPZigbeeGatewaySuspiciousEgressRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateIotRecord(
            source: "10.40.1.91",
            destination: "10.40.1.92",
            destinationPort: 5683,
            protocol: "UDP",
            service: "CoAP",
            info: "coap local telemetry",
            process: "gatewayd.exe",
            isUdp: true)));

        Assert.False(result.Matched);
    }

    [Fact]
    public void Migrated_iot_rules_register_rule_owned_precision_profiles()
    {
        _ = new R113_MQTTBrokerConnectionToUnapprovedHostRule();
        _ = new R120_ModbusTrafficOutsideApprovedSegmentRule();
        _ = new R122_CoAPZigbeeGatewaySuspiciousEgressRule();

        var r113 = RulePrecisionCatalog.GetProfile("R113", "IotOt", SeverityLevel.High);
        var r120 = RulePrecisionCatalog.GetProfile("R120", "IotOt", SeverityLevel.Critical);
        var r122 = RulePrecisionCatalog.GetProfile("R122", "IotOt", SeverityLevel.High);

        Assert.Contains(RuleTelemetryKind.OtIcsProtocol, r113.RequiredTelemetry);
        Assert.Equal(1, r120.Threshold);
        Assert.Equal(TimeSpan.FromMinutes(10), r122.Window);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 29, 9, 0, 0, DateTimeKind.Utc));

    private static TrafficRecord CreateIotRecord(
        string source,
        string destination,
        int destinationPort,
        string protocol,
        string service,
        string? info = null,
        string? process = null,
        string? host = null,
        bool isUdp = false)
        => new()
        {
            Source = source,
            Destination = destination,
            DestinationPort = destinationPort,
            Protocol = protocol,
            ApplicationProtocol = protocol,
            ApplicationService = service,
            Info = info,
            ProcessName = process,
            HttpHost = host,
            IsUdp = isUdp,
            IsTcp = !isUdp,
            Length = 2048,
            L4Len = 2048
        };

    private static DetectionEvent AssertSingleEvent(RuleEvaluationResult result, string ruleId, SeverityLevel minimumSeverity, double minimumConfidence)
    {
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(ruleId, evt.RuleId);
        Assert.True(evt.ConfidenceScore >= minimumConfidence, $"Expected confidence >= {minimumConfidence:F2} but got {evt.ConfidenceScore:F2}.");
        Assert.True(evt.Severity >= minimumSeverity);
        Assert.NotNull(evt.StructuredEvidence);
        return evt;
    }

    private static void AssertEvidence(DetectionEvent evt, params string[] expectedKeys)
    {
        var keys = evt.StructuredEvidence!.Items.Select(item => item.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var expected in expectedKeys)
            Assert.Contains(expected, keys);
    }
}
