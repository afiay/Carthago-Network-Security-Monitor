// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R994FinsBulkDataMemoryReadQualityTests
{
    private const string Primary="800002000100000700000101820000000100";
    private const string Secondary="80000200010000FE00FF0101827F00000100";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R994_PublicFinsBulkDataMemoryReadRule(),IndustrialBatchOperation.FinsBulkDataMemoryRead,9600,false,true,secondary?Secondary:Primary);

    [Theory]
    [InlineData("response",0,192)]
    [InlineData("no-response",0,129)]
    [InlineData("reserved",1,1)]
    [InlineData("gateway",2,3)]
    [InlineData("destination-network",3,1)]
    [InlineData("broadcast-node",4,255)]
    [InlineData("destination-unit",5,1)]
    [InlineData("source-network",6,1)]
    [InlineData("same-node",7,1)]
    [InlineData("source-unit",8,1)]
    [InlineData("write",11,2)]
    [InlineData("other-area",12,176)]
    [InlineData("bit-area",12,2)]
    [InlineData("start-out-of-range",13,128)]
    [InlineData("bit-offset",15,1)]
    [InlineData("count-512",16,2)]
    [InlineData("count-257",17,1)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R994_PublicFinsBulkDataMemoryReadRule(),IndustrialBatchOperation.FinsBulkDataMemoryRead,9600,false,true,
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
        => IndustrialBatchRuleAssertions.Negative(new R994_PublicFinsBulkDataMemoryReadRule(),IndustrialBatchOperation.FinsBulkDataMemoryRead,9600,false,true,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R994_PublicFinsBulkDataMemoryReadRule(),IndustrialBatchOperation.FinsBulkDataMemoryRead,9600,false,true,Primary);
}
