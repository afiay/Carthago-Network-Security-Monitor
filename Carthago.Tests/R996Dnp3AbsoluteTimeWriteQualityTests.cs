// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R996Dnp3AbsoluteTimeWriteQualityTests
{
    private const string Primary="056412C4010007001755C0C002320107010000000000003FC1";
    private const string Secondary="056412C40000EFFF73A9FFCF0232010701FFFFFFFFFFFF5409";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R996_PublicDnp3AbsoluteTimeWriteRule(),IndustrialBatchOperation.Dnp3AbsoluteTimeWrite,20000,false,true,secondary?Secondary:Primary);

    [Theory]
    [InlineData("wrong-link-direction",3,68)]
    [InlineData("equal-peer",6,1)]
    [InlineData("transport-fragment",10,64)]
    [InlineData("app-fragment",11,128)]
    [InlineData("app-confirm",11,224)]
    [InlineData("crc-header",8,22)]
    [InlineData("crc-data",24,192)]
    [InlineData("read",12,1)]
    [InlineData("wrong-group",13,51)]
    [InlineData("relative-time",14,3)]
    [InlineData("qualifier",15,6)]
    [InlineData("count",16,2)]
    [InlineData("link-length",2,17)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R996_PublicDnp3AbsoluteTimeWriteRule(),IndustrialBatchOperation.Dnp3AbsoluteTimeWrite,20000,false,true,
            IndustrialBatchWireFixtures.Mutate(Primary,name,offset,value,true));

    [Theory]
    [InlineData("reserved-destination","056412C4F0FF07000F57C0C002320107010000000000003FC1")]
    [InlineData("reserved-source","056412C40100F0FF465CC0C002320107010000000000003FC1")]
    public Task CompleteAlternativeWireNegative(string name,string hex)
        => IndustrialBatchRuleAssertions.Negative(new R996_PublicDnp3AbsoluteTimeWriteRule(),IndustrialBatchOperation.Dnp3AbsoluteTimeWrite,20000,false,true,IndustrialBatchWireFixtures.Decode(hex));

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
        => IndustrialBatchRuleAssertions.Negative(new R996_PublicDnp3AbsoluteTimeWriteRule(),IndustrialBatchOperation.Dnp3AbsoluteTimeWrite,20000,false,true,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R996_PublicDnp3AbsoluteTimeWriteRule(),IndustrialBatchOperation.Dnp3AbsoluteTimeWrite,20000,false,true,Primary);
}
