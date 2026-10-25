using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
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
}
