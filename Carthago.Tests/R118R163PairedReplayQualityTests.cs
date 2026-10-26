// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Engine.Rules.IotOt;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Offline paired fixtures exercise the distinction between an observed
/// credential request and independently corroborated attacker-controlled SSRF.
/// No fixture is sufficient to authorize automatic promotion to Alert.
/// </summary>
public sealed class R118R163PairedReplayQualityTests
{
    [Fact]
    public async Task Redacted_Onvif_Replay_Uses_Actual_Http_Parser_Derived_Flag()
    {
        var replayDirectory = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });

        var positive = Assert.Single(report.SampleResults, sample =>
            sample.Name == "r118-onvif-default-basic-redacted");
        var negative = Assert.Single(report.SampleResults, sample =>
            sample.Name == "r118-onvif-unknown-basic-redacted");

        Assert.Contains("R118", positive.ActualMatches);
        Assert.DoesNotContain("R118", negative.ActualMatches);
        Assert.Empty(positive.Errors);
        Assert.Empty(negative.Errors);
        Assert.True(positive.MaximumConfidence >= 0.75);

        // The known synthetic Basic wire token must not appear in exported
        // benchmark observations after parser-level redaction.
        var json = System.Text.Json.JsonSerializer.Serialize(report);
        Assert.DoesNotContain("YWRtaW46YWRtaW4=", json);
        foreach (var profile in report.ProfileResults.Keys)
            Assert.DoesNotContain("R118", positive.Profiles[profile].AlertRuleIds);
    }

    [Fact]
    public async Task Host_Authority_And_Iot_Target_Replays_Separate_Raw_Matches_From_Alerts()
    {
        var replayDirectory = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });

        var r163Duplicate = report.SampleResults.Single(sample =>
            sample.Name == "r163-duplicate-host-metadata-decoy");
        var r163Disagreement = report.SampleResults.Single(sample =>
            sample.Name == "r163-parsed-host-header-disagreement");
        var r163Azure = report.SampleResults.Single(sample =>
            sample.Name == "r163-azure-single-host-credential-probe");
        var r118Benign = report.SampleResults.Single(sample =>
            sample.Name == "r118-default-basic-unrelated-https-host");
        var r118Router = report.SampleResults.Single(sample =>
            sample.Name == "r118-router-lowercase-single-basic");

        Assert.True(report.SampleResults.Count >= 63);
        Assert.Equal(ReplaySampleClassification.Benign, r163Duplicate.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, r163Disagreement.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, r118Benign.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r163Azure.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r118Router.Classification);

        Assert.DoesNotContain("R163", r163Duplicate.ActualMatches);
        Assert.DoesNotContain("R163", r163Disagreement.ActualMatches);
        Assert.DoesNotContain("R118", r118Benign.ActualMatches);
        Assert.Contains("R163", r163Azure.ActualMatches);
        Assert.Contains("R118", r118Router.ActualMatches);
        Assert.All(new[] { r163Duplicate, r163Disagreement, r163Azure, r118Benign, r118Router },
            sample => Assert.Empty(sample.Errors));

        Assert.Equal(86, new R118_DefaultCredentialIoTAttemptRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(84, new R163_SsrfMetadataServiceProbeRule().PrecisionProfile.MinimumConfidence);
        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.DoesNotContain("R163", r163Azure.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R118", r118Router.Profiles[profile].AlertRuleIds);
            Assert.True(Assert.Single(r163Azure.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163").Confidence < 0.84);
            Assert.True(Assert.Single(r118Router.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118").Confidence < 0.86);
        }
    }

    [Fact]
    public async Task Matched_Iot_Default_And_Gcp_Token_Pairs_Stay_Shadow_While_Decoys_Do_Not_Match()
    {
        var replayDirectory = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });

        var r118Decoy = report.SampleResults.Single(sample =>
            sample.Name == "r118-iot-x-authorization-lookalike");
        var r118Attempt = report.SampleResults.Single(sample =>
            sample.Name == "r118-camera-support-default-basic-attempt");
        var r163Email = report.SampleResults.Single(sample =>
            sample.Name == "r163-gcp-service-account-email-not-token");
        var r163Token = report.SampleResults.Single(sample =>
            sample.Name == "r163-gcp-service-account-token-direct-shadow");

        Assert.True(report.SampleResults.Count >= 67);
        Assert.Equal(ReplaySampleClassification.Benign, r118Decoy.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r118Attempt.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, r163Email.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r163Token.Classification);
        Assert.DoesNotContain("R118", r118Decoy.ActualMatches);
        Assert.Contains("R118", r118Attempt.ActualMatches);
        Assert.DoesNotContain("R163", r163Email.ActualMatches);
        Assert.Contains("R163", r163Token.ActualMatches);
        Assert.All(new[] { r118Decoy, r118Attempt, r163Email, r163Token },
            sample => Assert.Empty(sample.Errors));

        Assert.Equal(86, new R118_DefaultCredentialIoTAttemptRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(84, new R163_SsrfMetadataServiceProbeRule().PrecisionProfile.MinimumConfidence);
        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.DoesNotContain("R118", r118Attempt.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", r163Token.Profiles[profile].AlertRuleIds);
            Assert.True(Assert.Single(r118Attempt.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118").Confidence < 0.86);
            Assert.True(Assert.Single(r163Token.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163").Confidence < 0.84);
        }
    }

    [Fact]
    public async Task New_Labeled_Replays_Preserve_R118_R163_Confidence_Gates_And_Alert_Precision()
    {
        var replayDirectory = Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");
        var report = await new TuningBenchmarkRunner().RunAsync(
            new TuningBenchmarkOptions { ReplayDirectory = replayDirectory });

        var r118Benign = report.SampleResults.Single(sample =>
            sample.Name == "r118-bearer-token-looks-like-default-basic");
        var r118Malicious = report.SampleResults.Single(sample =>
            sample.Name == "r118-ubiquiti-default-basic-observed");
        var r163Benign = report.SampleResults.Single(sample =>
            sample.Name == "r163-paired-unrelated-gcp-agent");
        var r163Malicious = report.SampleResults.Single(sample =>
            sample.Name == "r163-paired-gcp-unattributed-fetch-candidate");

        Assert.Equal(ReplaySampleClassification.Benign, r118Benign.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, r163Benign.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r118Malicious.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r163Malicious.Classification);

        Assert.DoesNotContain("R118", r118Benign.ActualMatches);
        // This authorized Bearer request is TLS-protected, so it is neither
        // a Basic default-credential attempt nor a cleartext Bearer exposure.
        Assert.DoesNotContain("R135", r118Benign.ActualMatches);
        Assert.DoesNotContain("R163", r163Benign.ActualMatches);
        Assert.Contains("R118", r118Malicious.ActualMatches);
        Assert.Contains("R163", r163Malicious.ActualMatches);
        Assert.Empty(r118Benign.Errors);
        Assert.Empty(r118Malicious.Errors);
        Assert.Empty(r163Benign.Errors);
        Assert.Empty(r163Malicious.Errors);

        Assert.Equal(86, new R118_DefaultCredentialIoTAttemptRule().PrecisionProfile.MinimumConfidence);
        Assert.Equal(84, new R163_SsrfMetadataServiceProbeRule().PrecisionProfile.MinimumConfidence);

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.DoesNotContain("R118", r118Malicious.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", r163Malicious.Profiles[profile].AlertRuleIds);

            var r118 = Assert.Single(r118Malicious.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118");
            var r163 = Assert.Single(r163Malicious.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163");
            Assert.True(r118.Confidence < 0.86, $"{profile}: R118 unexpectedly reached its 86% floor.");
            Assert.True(r163.Confidence < 0.84, $"{profile}: R163 unexpectedly reached its 84% floor.");
        }

        // Second paired batch: an ambiguous duplicate Authorization header is
        // not proof of a device login; a single origin Basic header still is.
        // Likewise, normalized-away metadata paths are not credential reads,
        // while the provider-documented GCP IPv6 token path is a raw candidate.
        var duplicateAuth = report.SampleResults.Single(sample =>
            sample.Name == "r118-duplicate-authorization-ambiguous");
        var singleAuth = report.SampleResults.Single(sample =>
            sample.Name == "r118-unauthorized-router-root-basic");
        var normalizedPath = report.SampleResults.Single(sample =>
            sample.Name == "r163-encoded-dot-segment-metadata-decoy");
        var ipv6CredentialPath = report.SampleResults.Single(sample =>
            sample.Name == "r163-gcp-ipv6-credential-fetch-unattributed");

        Assert.Equal(ReplaySampleClassification.Benign, duplicateAuth.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, singleAuth.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, normalizedPath.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, ipv6CredentialPath.Classification);
        Assert.DoesNotContain("R118", duplicateAuth.ActualMatches);
        Assert.DoesNotContain("R135", duplicateAuth.ActualMatches);
        Assert.Contains("R118", singleAuth.ActualMatches);
        Assert.DoesNotContain("R163", normalizedPath.ActualMatches);
        Assert.Contains("R163", ipv6CredentialPath.ActualMatches);
        Assert.Empty(duplicateAuth.Errors);
        Assert.Empty(singleAuth.Errors);
        Assert.Empty(normalizedPath.Errors);
        Assert.Empty(ipv6CredentialPath.Errors);

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.DoesNotContain("R118", singleAuth.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", ipv6CredentialPath.Profiles[profile].AlertRuleIds);

            var r118 = Assert.Single(singleAuth.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118");
            var r163 = Assert.Single(ipv6CredentialPath.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163");
            Assert.True(r118.Confidence < 0.86, $"{profile}: duplicate-auth batch unexpectedly promotes R118.");
            Assert.True(r163.Confidence < 0.84, $"{profile}: GCP IPv6 batch unexpectedly promotes R163.");
        }

        // Third paired batch: device identity must be a host-label signal,
        // not a keyword embedded in a marketing domain. An executable with
        // a guest-agent basename in a writable path must not be silently
        // suppressed as an approved cloud agent.
        var r118Marketing = report.SampleResults.Single(sample =>
            sample.Name == "r118-camera-marketing-host-substring");
        var r118Router02 = report.SampleResults.Single(sample =>
            sample.Name == "r118-router02-inventory-label-default-basic");
        var r163ApprovedAgent = report.SampleResults.Single(sample =>
            sample.Name == "r163-approved-cloud-init-install-path");
        var r163SpoofedAgent = report.SampleResults.Single(sample =>
            sample.Name == "r163-cloud-init-writable-path-spoof");

        Assert.True(report.SampleResults.Count >= 71);
        Assert.Equal(ReplaySampleClassification.Benign, r118Marketing.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r118Router02.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, r163ApprovedAgent.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r163SpoofedAgent.Classification);
        Assert.DoesNotContain("R118", r118Marketing.ActualMatches);
        Assert.Contains("R118", r118Router02.ActualMatches);
        Assert.DoesNotContain("R163", r163ApprovedAgent.ActualMatches);
        foreach (var unrelatedTokenRule in new[] { "R353", "R354", "R359" })
            Assert.DoesNotContain(unrelatedTokenRule, r163ApprovedAgent.ActualMatches);
        Assert.Contains("R163", r163SpoofedAgent.ActualMatches);
        Assert.All(new[] { r118Marketing, r118Router02, r163ApprovedAgent, r163SpoofedAgent },
            sample => Assert.Empty(sample.Errors));

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.Empty(r163ApprovedAgent.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R118", r118Router02.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", r163SpoofedAgent.Profiles[profile].AlertRuleIds);
            var r118Decision = Assert.Single(r118Router02.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118");
            var r163Decision = Assert.Single(r163SpoofedAgent.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163");
            Assert.True(r118Decision.Confidence < 0.86, $"{profile}: R118 unexpectedly promoted.");
            Assert.True(r163Decision.Confidence < 0.84, $"{profile}: R163 unexpectedly promoted.");
        }

        // Fourth paired batch uses capture-time redacted Basic evidence and
        // GCP guest-agent path attribution. Neither header redaction nor a
        // familiar executable basename may substitute for trusted evidence.
        var r118UnknownBasic = report.SampleResults.Single(sample =>
            sample.Name == "r118-onvif-unknown-basic-redacted");
        var r118DefaultBasic = report.SampleResults.Single(sample =>
            sample.Name == "r118-onvif-default-basic-redacted");
        var r163InstalledAgent = report.SampleResults.Single(sample =>
            sample.Name == "r163-gcp-guest-agent-installed-path");
        var r163WritableSpoof = report.SampleResults.Single(sample =>
            sample.Name == "r163-gcp-user-writable-agent-spoof");

        Assert.True(report.SampleResults.Count >= 78);
        Assert.Equal(ReplaySampleClassification.Benign, r118UnknownBasic.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r118DefaultBasic.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, r163InstalledAgent.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r163WritableSpoof.Classification);
        Assert.DoesNotContain("R118", r118UnknownBasic.ActualMatches);
        Assert.Contains("R118", r118DefaultBasic.ActualMatches);
        Assert.DoesNotContain("R163", r163InstalledAgent.ActualMatches);
        Assert.Contains("R163", r163WritableSpoof.ActualMatches);
        Assert.All(new[] { r118UnknownBasic, r118DefaultBasic, r163InstalledAgent, r163WritableSpoof },
            sample => Assert.Empty(sample.Errors));

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.DoesNotContain("R118", r118DefaultBasic.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", r163WritableSpoof.Profiles[profile].AlertRuleIds);
            Assert.True(Assert.Single(r118DefaultBasic.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118").Confidence < 0.86);
            Assert.True(Assert.Single(r163WritableSpoof.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163").Confidence < 0.84);
        }

        // Fifth paired batch: the real HTTP parser must redact a non-default
        // ONVIF Basic value without manufacturing R118 evidence. An unapproved
        // IMDSv2 HEAD request is a raw metadata-path probe, not SSRF proof.
        var r118NonDefault = report.SampleResults.Single(sample =>
            sample.Name == "r118-onvif-nondefault-basic-wire-redacted");
        var r163HeadProbe = report.SampleResults.Single(sample =>
            sample.Name == "r163-unapproved-aws-imdsv2-head-credential-probe");

        Assert.True(report.SampleResults.Count >= 80);
        Assert.Equal(ReplaySampleClassification.Benign, r118NonDefault.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, r163HeadProbe.Classification);
        Assert.DoesNotContain("R118", r118NonDefault.ActualMatches);
        Assert.Contains("R163", r163HeadProbe.ActualMatches);
        Assert.Empty(r118NonDefault.Errors);
        Assert.Empty(r163HeadProbe.Errors);
        Assert.DoesNotContain("YWRtaW46c3Ryb25nLXBhc3M=",
            System.Text.Json.JsonSerializer.Serialize(report));
        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.Empty(r118NonDefault.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", r163HeadProbe.Profiles[profile].AlertRuleIds);
            Assert.True(Assert.Single(r163HeadProbe.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163").Confidence < 0.84);
        }

        // Sixth paired batch: a forwarded Host cannot establish an IoT target,
        // and a legitimate IMDSv2 token PUT cannot establish SSRF. Their
        // positive counterparts remain non-paging until independently verified.
        var forwardedHost = report.SampleResults.Single(sample =>
            sample.Name == "r118-forwarded-camera-host-unrelated-https");
        var wireDefault = report.SampleResults.Single(sample =>
            sample.Name == "r118-camera-default-basic-wire-probe");
        var imdsSession = report.SampleResults.Single(sample =>
            sample.Name == "r163-approved-imdsv2-session-put");
        var imdsCredentialGet = report.SampleResults.Single(sample =>
            sample.Name == "r163-unapproved-imdsv2-get-credential-path");

        Assert.Equal(ReplaySampleClassification.Benign, forwardedHost.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, wireDefault.Classification);
        Assert.Equal(ReplaySampleClassification.Benign, imdsSession.Classification);
        Assert.Equal(ReplaySampleClassification.Malicious, imdsCredentialGet.Classification);
        Assert.DoesNotContain("R118", forwardedHost.ActualMatches);
        Assert.Contains("R118", wireDefault.ActualMatches);
        Assert.DoesNotContain("R163", imdsSession.ActualMatches);
        Assert.Contains("R163", imdsCredentialGet.ActualMatches);
        Assert.All(new[] { forwardedHost, wireDefault, imdsSession, imdsCredentialGet },
            sample => Assert.Empty(sample.Errors));

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.Empty(forwardedHost.Profiles[profile].AlertRuleIds);
            Assert.Empty(imdsSession.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R118", wireDefault.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", imdsCredentialGet.Profiles[profile].AlertRuleIds);
            Assert.True(Assert.Single(wireDefault.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R118").Confidence < 0.86);
            Assert.True(Assert.Single(imdsCredentialGet.Profiles[profile].RuleDecisions,
                decision => decision.RuleId == "R163").Confidence < 0.84);
        }
        // Seventh paired batch: source authority and executable path
        // ambiguity must not manufacture evidence. Both provider-specific
        // positive candidates still remain non-paging at existing floors.
        var conflictingHost = report.SampleResults.Single(sample =>
            sample.Name == "r118-conflicting-host-default-basic-over-tls");
        var supportPair = report.SampleResults.Single(sample =>
            sample.Name == "r118-router-support-parser-default-basic");
        var cloudInitHomeSpoof = report.SampleResults.Single(sample =>
            sample.Name == "r163-home-cloud-init-basename-spoof");
        var cloudInitHead = report.SampleResults.Single(sample =>
            sample.Name == "r163-approved-cloud-init-imdsv2-head");

        Assert.True(report.SampleResults.Count >= 88);
        Assert.DoesNotContain("R118", conflictingHost.ActualMatches);
        Assert.Contains("R118", supportPair.ActualMatches);
        Assert.Contains("R163", cloudInitHomeSpoof.ActualMatches);
        Assert.DoesNotContain("R163", cloudInitHead.ActualMatches);
        Assert.All(new[] { conflictingHost, supportPair, cloudInitHomeSpoof, cloudInitHead },
            sample => Assert.Empty(sample.Errors));
        Assert.DoesNotContain("c3VwcG9ydDpzdXBwb3J0",
            System.Text.Json.JsonSerializer.Serialize(report), StringComparison.Ordinal);

        foreach (var profile in report.ProfileResults.Keys)
        {
            Assert.Empty(conflictingHost.Profiles[profile].AlertRuleIds);
            Assert.Empty(cloudInitHead.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R118", supportPair.Profiles[profile].AlertRuleIds);
            Assert.DoesNotContain("R163", cloudInitHomeSpoof.Profiles[profile].AlertRuleIds);
        }

        // Recommendation heuristics must not override the rule-specific
        // precision floors simply because a raw match exceeded 75%.
        Assert.DoesNotContain("R118", report.Summary.RulesRecommendedForAlert);
        Assert.DoesNotContain("R163", report.Summary.RulesRecommendedForAlert);

        // Sample-level metrics count actual alerts, not raw detector matches.
        // A benign alert in any profile is a regression requiring investigation.
        Assert.All(report.Summary.SampleLevelQualityByProfile.Values,
            quality => Assert.Equal(0, quality.FalsePositives));
    }
}
