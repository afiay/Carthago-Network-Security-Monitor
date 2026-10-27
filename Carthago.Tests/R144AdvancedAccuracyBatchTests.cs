// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R144AdvancedAccuracyBatchTests
{
    [Fact] public async Task Ten_Year_External_Certificate_Is_Candidate()
    {
        var result = await new R144_CertificateValidityPeriodTooLongRule().EvaluateAsync(
            NetworkBatch141145Context.At(NetworkBatch141145Context.LongValidity()));
        Assert.True(result.Matched);
        Assert.Equal("R144", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Normal_One_Year_Certificate_Is_Benign()
    {
        var record = NetworkBatch141145Context.Tls();
        record.CertValidTo = new DateTime(2027, 9, 30, 0, 0, 0, DateTimeKind.Utc);
        Assert.False((await new R144_CertificateValidityPeriodTooLongRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Missing_Certificate_Dates_Do_Not_Match()
    {
        var record = NetworkBatch141145Context.LongValidity();
        record.CertValidFrom = null;
        Assert.False((await new R144_CertificateValidityPeriodTooLongRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Reversed_Dates_Do_Not_Match()
    {
        var record = NetworkBatch141145Context.LongValidity();
        record.CertValidFrom = new DateTime(2031, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        Assert.False((await new R144_CertificateValidityPeriodTooLongRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Internal_Socket_Is_Not_Public_Certificate_Exposure()
    {
        var record = NetworkBatch141145Context.LongValidity();
        record.Destination = "10.144.0.12";
        Assert.False((await new R144_CertificateValidityPeriodTooLongRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Contradictory_Udp_Transport_Is_Rejected()
    {
        var record = NetworkBatch141145Context.LongValidity();
        NetworkBatch141145Context.AsUdp(record);
        Assert.False((await new R144_CertificateValidityPeriodTooLongRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Plain_Tcp_With_Certificate_Info_Is_Not_Tls_Proof()
    {
        var record = NetworkBatch141145Context.LongValidity();
        record.Protocol = "TCP";
        record.ApplicationProtocol = "TCP";
        record.ApplicationService = "TCP";
        record.Info = "TLS cert valid until 2030";
        Assert.False((await new R144_CertificateValidityPeriodTooLongRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Numeric_Validity_Evidence_And_Default_Shadow_Are_Preserved()
    {
        var rule = new R144_CertificateValidityPeriodTooLongRule();
        var evt = Assert.Single((await rule.EvaluateAsync(
            NetworkBatch141145Context.At(NetworkBatch141145Context.LongValidity()))).Events);
        Assert.Contains(evt.StructuredEvidence!.Items, item => item.Key == "tls.validityDays");
        Assert.Equal(70, rule.PrecisionProfile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
    }
}
