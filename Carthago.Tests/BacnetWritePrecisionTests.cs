using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Services.EnvironmentTuning;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class BacnetWritePrecisionTests
{
    [Theory]
    [InlineData("BACnet ReadProperty request object=analogOutput")]
    [InlineData("BACnet device inventory request")]
    public async Task R485_Does_Not_Interpret_Benign_Bacnet_As_Write(string description)
    {
        var record = new TrafficRecord
        {
            Source = "10.20.0.44", Destination = "10.21.0.66", Protocol = "UDP",
            ApplicationProtocol = "BACnet", DestinationPort = 47808, Info = description
        };

        var result = await new R485_BACnetWritePropertyRequestRule().EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task External_Bacnet_Write_Uses_Verified_Ot_Inventory_For_Precision_Eligibility()
    {
        var record = new TrafficRecord
        {
            Source = "203.0.113.44", Destination = "10.20.0.66", Protocol = "UDP",
            ApplicationProtocol = "BACnet", DestinationPort = 47808,
            Info = "BACnet WriteProperty request object=analogOutput"
        };
        var rule = new R485_BACnetWritePropertyRequestRule();
        var detection = await rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        Assert.True(detection.Matched);
        var evt = Assert.Single(detection.Events);
        var configured = new ApprovedAssetRegistry(new EnvironmentTuningOptions
        {
            Approved = new ApprovedEnvironmentOptions { OtSegments = { "10.20.0.0/24" } }
        });

        var withoutInventory = RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor, evt, record,
            RuleMode.Alert, "OTSegment", new ApprovedAssetRegistry(new EnvironmentTuningOptions()));
        var withInventory = RulePrecisionRuntimeEvaluator.Evaluate(rule.Descriptor, evt, record,
            RuleMode.Alert, "OTSegment", configured);

        Assert.Equal(RuleMode.Shadow, withoutInventory.EffectiveMode);
        Assert.Equal(RuleMode.Alert, withInventory.EffectiveMode);
    }
}
