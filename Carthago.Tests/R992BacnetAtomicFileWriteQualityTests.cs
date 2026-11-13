// SPDX-License-Identifier: MIT
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R992BacnetAtomicFileWriteQualityTests
{
    private const string Primary="810A0117010400050707C4028000010E310065FE0100505249564154452D4241434E45542D46494C45131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9FA0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBFC0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDFE0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF0F";
    private const string Secondary="810A011701070205FF07C402BFFFFE0E310065FE0100AFADB6A9BEABBAD2BDBEBCB1BAABD2B9B6B3BAECEBEAE9E8E7E6E5E4E3E2E1E0DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A09F9E9D9C9B9A999897969594939291908F8E8D8C8B8A898887868584838281807F7E7D7C7B7A797877767574737271706F6E6D6C6B6A696867666564636261605F5E5D5C5B5A595857565554535251504F4E4D4C4B4A494847464544434241403F3E3D3C3B3A393837363534333231302F2E2D2C2B2A292827262524232221201F1E1D1C1B1A191817161514131211100F0E0D0C0B0A090807060504030201000F";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public Task PositiveWireAndNonconvergence(bool secondary)
        => IndustrialBatchRuleAssertions.Positive(new R992_PublicBacnetAtomicFileWriteRule(),IndustrialBatchOperation.BacnetAtomicFileWrite,47808,false,false,secondary?Secondary:Primary);

    [Theory]
    [InlineData("bvlc-function",1,11)]
    [InlineData("bvlc-length",3,0)]
    [InlineData("npdu-version",4,2)]
    [InlineData("routed",5,36)]
    [InlineData("no-reply",5,0)]
    [InlineData("segmented",6,8)]
    [InlineData("invalid-max-apdu",7,6)]
    [InlineData("object-type",11,255)]
    [InlineData("other-service",9,6)]
    [InlineData("object-tag",10,12)]
    [InlineData("record-access",15,30)]
    [InlineData("signed-tag",16,33)]
    [InlineData("position",17,1)]
    [InlineData("octet-tag",18,117)]
    [InlineData("length-form",19,253)]
    [InlineData("octet-length",20,2)]
    [InlineData("closing",278,31)]
    public Task SemanticAndHeaderNegative(string name,int offset,int value)
        => IndustrialBatchRuleAssertions.Negative(new R992_PublicBacnetAtomicFileWriteRule(),IndustrialBatchOperation.BacnetAtomicFileWrite,47808,false,false,
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
        => IndustrialBatchRuleAssertions.Negative(new R992_PublicBacnetAtomicFileWriteRule(),IndustrialBatchOperation.BacnetAtomicFileWrite,47808,false,false,IndustrialBatchWireFixtures.Decode(Primary),variant);

    [Fact]
    public Task CaptureProofCooldownAndIsolation()
        => IndustrialBatchRuleAssertions.ProofAndState(()=>new R992_PublicBacnetAtomicFileWriteRule(),IndustrialBatchOperation.BacnetAtomicFileWrite,47808,false,false,Primary);
}
