// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R997ModbusReadWriteSamePairZeroQualityTests
{
    private const string Primary="00010000000F011700000002000000020400000000";
    private const string Secondary="FFFF0000000FF717FFFE0002FFFE00020400000000";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R997_PublicModbusReadWriteSamePairZeroRule(),IndustrialBatchOperation.ModbusReadWriteSamePairZero,502,true,false,secondary?Secondary:Primary);

    [Theory]
    [InlineData("protocol",3,1)]
    [InlineData("mbap-length",5,0)]
    [InlineData("unit-zero",6,0)]
    [InlineData("unit-248",6,248)]
    [InlineData("other-function",7,6)]
    [InlineData("read-qty",11,1)]
    [InlineData("write-address",13,1)]
    [InlineData("write-qty",15,1)]
    [InlineData("byte-count",16,2)]
    [InlineData("first-value",18,1)]
    [InlineData("last-value",20,1)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R997_PublicModbusReadWriteSamePairZeroRule(),IndustrialBatchOperation.ModbusReadWriteSamePairZero,502,true,false,
            IndustrialBatchWireFixtures.Mutate(Primary,name,offset,value,false));

    [Theory]
    [InlineData("crosses-register-end","00010000000F0117FFFF0002FFFF00020400000000")]
    public Task CompleteAlternativeWireNegative(string name,string hex)
        => IndustrialBatchRuleAssertions.Negative(new R997_PublicModbusReadWriteSamePairZeroRule(),IndustrialBatchOperation.ModbusReadWriteSamePairZero,502,true,false,IndustrialBatchWireFixtures.Decode(hex));

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
    [InlineData("no-syn")]
    [InlineData("no-synack")]
    [InlineData("wrong-synack")]
    [InlineData("wrong-ack")]
    [InlineData("gap")]
    [InlineData("retransmit")]
    [InlineData("second-payload")]
    [InlineData("server-first")]
    [InlineData("fin-before")]
    [InlineData("fragmented-payload")]
    [InlineData("non-psh")]
    [InlineData("response")]
    public Task ScopeTransportAndCaptureNegative(string variant)
        => IndustrialBatchRuleAssertions.Negative(new R997_PublicModbusReadWriteSamePairZeroRule(),IndustrialBatchOperation.ModbusReadWriteSamePairZero,502,true,false,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R997_PublicModbusReadWriteSamePairZeroRule(),IndustrialBatchOperation.ModbusReadWriteSamePairZero,502,true,false,Primary);
}
