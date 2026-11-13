// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R991BacnetAtomicFileReadQualityTests
{
    private const string Primary="810A0016010400050706C4028000010E31002202000F";
    private const string Secondary="810A001601070205FF06C402BFFFFE0E31002202000F";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R991_PublicBacnetAtomicFileReadRule(),IndustrialBatchOperation.BacnetAtomicFileRead,47808,false,false,secondary?Secondary:Primary);

    [Theory]
    [InlineData("bvlc-function",1,11)]
    [InlineData("bvlc-length",3,0)]
    [InlineData("npdu-version",4,2)]
    [InlineData("routed",5,36)]
    [InlineData("no-reply",5,0)]
    [InlineData("segmented",6,8)]
    [InlineData("invalid-max-apdu",7,6)]
    [InlineData("object-type",11,255)]
    [InlineData("other-service",9,7)]
    [InlineData("object-tag",10,12)]
    [InlineData("record-access",15,30)]
    [InlineData("signed-tag",16,33)]
    [InlineData("nonzero-position",17,1)]
    [InlineData("count-tag",18,33)]
    [InlineData("count-256",19,1)]
    [InlineData("closing",21,31)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R991_PublicBacnetAtomicFileReadRule(),IndustrialBatchOperation.BacnetAtomicFileRead,47808,false,false,
            IndustrialBatchWireFixtures.Mutate(Primary,name,offset,value,false));

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
        => IndustrialBatchRuleAssertions.Negative(new R991_PublicBacnetAtomicFileReadRule(),IndustrialBatchOperation.BacnetAtomicFileRead,47808,false,false,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R991_PublicBacnetAtomicFileReadRule(),IndustrialBatchOperation.BacnetAtomicFileRead,47808,false,false,Primary);
}
