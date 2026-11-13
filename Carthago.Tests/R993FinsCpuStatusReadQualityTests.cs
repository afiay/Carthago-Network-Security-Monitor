// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R993FinsCpuStatusReadQualityTests
{
    private const string Primary="800002000100000700000601";
    private const string Secondary="80000200010000FE00FF0601";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R993_PublicFinsCpuStatusReadRule(),IndustrialBatchOperation.FinsCpuStatusRead,9600,false,true,secondary?Secondary:Primary);

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
    [InlineData("stop-command",10,4)]
    [InlineData("other-subcommand",11,2)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R993_PublicFinsCpuStatusReadRule(),IndustrialBatchOperation.FinsCpuStatusRead,9600,false,true,
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
        => IndustrialBatchRuleAssertions.Negative(new R993_PublicFinsCpuStatusReadRule(),IndustrialBatchOperation.FinsCpuStatusRead,9600,false,true,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R993_PublicFinsCpuStatusReadRule(),IndustrialBatchOperation.FinsCpuStatusRead,9600,false,true,Primary);
}
