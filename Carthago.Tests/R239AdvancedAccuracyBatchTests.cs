// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R239AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch236240Context.Sample(239);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch236240Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R239_Zigbee2MqttBridgeInternetAccessRule().EvaluateAsync(At(r))).Matched;
    [Fact] public async Task Attributed_Parsed_Mqtt_Publish_To_External_Broker_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Local_Broker_Is_Benign()
    { var r = Sample(); r.Destination = "10.236.0.30"; Assert.False(await Hit(r)); }
    [Fact] public async Task Info_Zigbee_Spoof_Without_Process_Is_Rejected()
    { var r = Sample(); r.ProcessName = null; r.Info = "zigbee2mqtt topic=control"; Assert.False(await Hit(r)); }
    [Fact] public async Task Generic_Mqtt_Client_Is_Not_Zigbee_Bridge()
    { var r = Sample(); r.ProcessName = "mqtt-client.exe"; Assert.False(await Hit(r)); }
    [Fact] public async Task Unparsed_Publish_Is_Rejected()
    { var r = Sample(); r.MqttPublishTopicObserved = false; Assert.False(await Hit(r)); }
    [Fact] public async Task Tls_Without_Decryption_Is_Rejected()
    { var r = Sample(); r.DestinationPort = 8883; r.TlsVersion = "TLS1.3"; Assert.False(await Hit(r)); }
    [Fact] public async Task Parsed_Mqtt_Connect_Also_Qualifies()
    { var r = Sample(); r.ApplicationProtocol = "mqtt.connect"; r.MqttPublishTopicObserved = false;
      Assert.True(await Hit(r)); }
    [Fact] public async Task Duplicate_Id_Does_Not_Match_Twice()
    { var rule = new R239_Zigbee2MqttBridgeInternetAccessRule(); var r = Sample();
      Assert.True((await rule.EvaluateAsync(At(r))).Matched);
      Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched); }
    [Fact] public async Task Raw_Topic_And_Info_Are_Not_Persisted()
    { var r = Sample(); r.Info = "topic=zigbee2mqtt/secret-topic-marker password=secret-mqtt-marker";
      var result = await new R239_Zigbee2MqttBridgeInternetAccessRule().EvaluateAsync(At(r));
      Assert.True(result.Matched); var e = Assert.Single(result.Events);
      Assert.DoesNotContain("secret-topic-marker", e.Evidence ?? "", StringComparison.Ordinal);
      Assert.DoesNotContain(e.StructuredEvidence!.Items, i => i.Value.Contains("secret-mqtt-marker", StringComparison.Ordinal)); }
    [Fact] public void Original_Alert_Mode_And_Floor()
    { var p = new R239_Zigbee2MqttBridgeInternetAccessRule().PrecisionProfile;
      Assert.Equal(84, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode); }
}
