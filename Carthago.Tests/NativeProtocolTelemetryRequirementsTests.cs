using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NativeProtocolTelemetryRequirementsTests
{
    [Fact]
    public void Telnet_Default_Credentials_Do_Not_Require_Http()
    {
        var rule = RuleRegistry.CreateDefaultRules().Single(rule => rule.Descriptor.RuleId == "R118");
        var record = new TrafficRecord
        {
            Source = "10.0.0.72", Destination = "10.0.0.150", Protocol = "TCP",
            DestinationPort = 23, Info = "telnet login admin:admin factory default"
        };

        var result = RuleTelemetryValidator.Validate(rule, record);
        Assert.True(result.CanRunSafely, string.Join(", ", result.MissingRequiredTelemetry));
        Assert.DoesNotContain("precision.Http", result.MissingRequiredTelemetry);
    }

    [Fact]
    public void Native_Redis_Config_Command_Does_Not_Require_Http()
    {
        var rule = RuleRegistry.CreateDefaultRules().Single(rule => rule.Descriptor.RuleId == "R437");
        var record = new TrafficRecord
        {
            Source = "10.0.0.65", Destination = "10.10.0.65", Protocol = "TCP",
            DestinationPort = 6379, ApplicationProtocol = "Redis", Info = "CONFIG SET dir /tmp"
        };

        var result = RuleTelemetryValidator.Validate(rule, record);
        Assert.True(result.CanRunSafely, string.Join(", ", result.MissingRequiredTelemetry));
        Assert.DoesNotContain("precision.Http", result.MissingRequiredTelemetry);
    }
}
