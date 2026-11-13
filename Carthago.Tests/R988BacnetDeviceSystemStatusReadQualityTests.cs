// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R988BacnetDeviceSystemStatusReadQualityTests
{
    private const string Primary="810A001101040005070C0C020000011970";
    private const string Secondary="810A001101070205FF0C0C023FFFFE1970";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R988_PublicBacnetDeviceSystemStatusReadRule(),IndustrialBatchOperation.BacnetDeviceSystemStatusRead,47808,false,false,secondary?Secondary:Primary);

    [Theory]
    [InlineData("bvlc-function",1,11)]
    [InlineData("bvlc-length",3,0)]
    [InlineData("npdu-version",4,2)]
    [InlineData("routed",5,36)]
    [InlineData("no-reply",5,0)]
    [InlineData("segmented",6,8)]
    [InlineData("invalid-max-apdu",7,6)]
    [InlineData("object-type",11,255)]
    [InlineData("other-service",9,14)]
    [InlineData("object-tag",10,28)]
    [InlineData("object-list",16,76)]
    [InlineData("property-tag",15,41)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R988_PublicBacnetDeviceSystemStatusReadRule(),IndustrialBatchOperation.BacnetDeviceSystemStatusRead,47808,false,false,
            IndustrialBatchWireFixtures.Mutate(Primary,name,offset,value,false));

    [Theory]
    [InlineData("wildcard-instance","810A001101040005070C0C023FFFFF1970")]
    public Task CompleteAlternativeWireNegative(string name,string hex)
        => IndustrialBatchRuleAssertions.Negative(new R988_PublicBacnetDeviceSystemStatusReadRule(),IndustrialBatchOperation.BacnetDeviceSystemStatusRead,47808,false,false,IndustrialBatchWireFixtures.Decode(hex));

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
        => IndustrialBatchRuleAssertions.Negative(new R988_PublicBacnetDeviceSystemStatusReadRule(),IndustrialBatchOperation.BacnetDeviceSystemStatusRead,47808,false,false,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R988_PublicBacnetDeviceSystemStatusReadRule(),IndustrialBatchOperation.BacnetDeviceSystemStatusRead,47808,false,false,Primary);
}
