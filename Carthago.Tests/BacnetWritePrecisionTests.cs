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
    public async Task Unverified_Bacnet_WriteProperty_Text_Cannot_Substitute_For_Confirmed_Apdu()
    {
        var record = new TrafficRecord
        {
            Source = "203.0.113.44", Destination = "10.20.0.66", Protocol = "UDP",
            ApplicationProtocol = "BACnet", DestinationPort = 47808,
            Info = "BACnet WriteProperty request object=analogOutput"
        };
        var rule = new R485_BACnetWritePropertyRequestRule();
        var detection = await rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        // This fixture has only a descriptive Info string, not a parser-decoded
        // confirmed BACnet WriteProperty APDU. It must not produce an event.
        // The missing positive remains visible in the labeled replay benchmark.
        Assert.False(detection.Matched);
        Assert.Empty(detection.Events);
        Assert.Contains(detection.NoMatchReasons,
            reason => reason.Code == "BACNET_WRITEPROPERTY_CONFIRMED_REQUEST_UNAVAILABLE");
    }
}
