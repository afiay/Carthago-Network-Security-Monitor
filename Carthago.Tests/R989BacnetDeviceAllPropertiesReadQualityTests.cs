// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R989BacnetDeviceAllPropertiesReadQualityTests
{
    private const string Primary="810A001301040005070E0C020000011E09081F";
    private const string Secondary="810A001301070205FF0E0C023FFFFE1E09081F";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R989_PublicBacnetDeviceAllPropertiesReadRule(),IndustrialBatchOperation.BacnetDeviceAllPropertiesRead,47808,false,false,secondary?Secondary:Primary);

    [Theory]
    [InlineData("bvlc-function",1,11)]
    [InlineData("bvlc-length",3,0)]
    [InlineData("npdu-version",4,2)]
    [InlineData("routed",5,36)]
    [InlineData("no-reply",5,0)]
    [InlineData("segmented",6,8)]
    [InlineData("invalid-max-apdu",7,6)]
    [InlineData("object-type",11,255)]
    [InlineData("other-service",9,12)]
    [InlineData("object-tag",10,28)]
    [InlineData("opening",15,46)]
    [InlineData("property-tag",16,25)]
    [InlineData("required-properties-only",17,105)]
    [InlineData("closing",18,47)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R989_PublicBacnetDeviceAllPropertiesReadRule(),IndustrialBatchOperation.BacnetDeviceAllPropertiesRead,47808,false,false,
            IndustrialBatchWireFixtures.Mutate(Primary,name,offset,value,false));

    [Theory]
    [InlineData("wildcard-instance","810A001301040005070E0C023FFFFF1E09081F")]
    public Task CompleteAlternativeWireNegative(string name,string hex)
        => IndustrialBatchRuleAssertions.Negative(new R989_PublicBacnetDeviceAllPropertiesReadRule(),IndustrialBatchOperation.BacnetDeviceAllPropertiesRead,47808,false,false,IndustrialBatchWireFixtures.Decode(hex));

    [Theory]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("coalesced")]
    [InlineData("empty")]
    [InlineData("wrong-port")]
    [InlineData("wrong-source-port")]
    [InlineData("private-source")]
    [InlineData("public-destination")]
    [InlineData("ip-incomplete")]
    [InlineData("ip-fragment")]
    [InlineData("wrong-transport")]
    [InlineData("udp-length")]
    public Task ScopeTransportAndCaptureNegative(string variant)
        => IndustrialBatchRuleAssertions.Negative(new R989_PublicBacnetDeviceAllPropertiesReadRule(),IndustrialBatchOperation.BacnetDeviceAllPropertiesRead,47808,false,false,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R989_PublicBacnetDeviceAllPropertiesReadRule(),IndustrialBatchOperation.BacnetDeviceAllPropertiesRead,47808,false,false,Primary);
}
