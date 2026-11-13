// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R995Dnp3IntegrityReadQualityTests
{
    private const string Primary="056414C401000700CE3EC0C0013C01063C02063C03063C04069C09";
    private const string Secondary="056414C40000EFFFAAC2FFCF013C04063C02063C01063C03062562";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R995_PublicDnp3IntegrityReadRule(),IndustrialBatchOperation.Dnp3IntegrityRead,20000,false,true,secondary?Secondary:Primary);

    [Theory]
    [InlineData("wrong-link-direction",3,68)]
    [InlineData("equal-peer",6,1)]
    [InlineData("transport-fragment",10,64)]
    [InlineData("app-fragment",11,128)]
    [InlineData("app-confirm",11,224)]
    [InlineData("crc-header",8,207)]
    [InlineData("crc-data",26,8)]
    [InlineData("write",12,2)]
    [InlineData("wrong-group",13,59)]
    [InlineData("duplicate-class",14,2)]
    [InlineData("wrong-qualifier",15,7)]
    [InlineData("invalid-class",17,5)]
    [InlineData("link-length",2,19)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R995_PublicDnp3IntegrityReadRule(),IndustrialBatchOperation.Dnp3IntegrityRead,20000,false,true,
            IndustrialBatchWireFixtures.Mutate(Primary,name,offset,value,true));

    [Theory]
    [InlineData("reserved-destination","056414C4F0FF0700D63CC0C0013C01063C02063C03063C04069C09")]
    [InlineData("reserved-source","056414C40100F0FF9F37C0C0013C01063C02063C03063C04069C09")]
    [InlineData("partial-classes","056411C40100070047C6C0C0013C01063C02063C0306CFAE")]
    public Task CompleteAlternativeWireNegative(string name,string hex)
        => IndustrialBatchRuleAssertions.Negative(new R995_PublicDnp3IntegrityReadRule(),IndustrialBatchOperation.Dnp3IntegrityRead,20000,false,true,IndustrialBatchWireFixtures.Decode(hex));

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
        => IndustrialBatchRuleAssertions.Negative(new R995_PublicDnp3IntegrityReadRule(),IndustrialBatchOperation.Dnp3IntegrityRead,20000,false,true,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R995_PublicDnp3IntegrityReadRule(),IndustrialBatchOperation.Dnp3IntegrityRead,20000,false,true,Primary);
}
