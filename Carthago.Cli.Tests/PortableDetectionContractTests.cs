// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Models;
using Carthago.Engine.Rules;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableDetectionContractTests
{
    private static readonly DateTime Epoch=new(2026,1,1,0,0,0,DateTimeKind.Utc);
    private static RuleDescriptor Descriptor()=>new("R001","Fixture","Network","Synthetic contract fixture",SeverityLevel.High,"R001",true);

    [Fact]
    public void ContractTypesHaveOnePortableOwner()
    {
        var core=typeof(DetectionEvent).Assembly;
        Assert.Equal("Carthago.Core",core.GetName().Name);
        foreach(var type in new[]{typeof(Carthago.Models.SeverityLevel),typeof(Carthago.Models.DetectionDeliveryStatus),typeof(Carthago.Models.DetectionSuppressionStatus),typeof(Carthago.Models.DetectionConfidenceLabel),typeof(Carthago.Models.DetectionEvidenceItem),typeof(Carthago.Models.DetectionEvidenceSet),typeof(Carthago.Models.ExternalSinkDeliveryStatus),typeof(Carthago.Models.DetectionEvent),typeof(Carthago.Models.Sensitivity),typeof(Carthago.Models.SensitivityExtensions),typeof(Carthago.Engine.Rules.RuleDescriptor),typeof(Carthago.Engine.Rules.RuleMode),typeof(Carthago.Engine.Rules.RuleNoMatchReasonCategory),typeof(Carthago.Engine.Rules.RuleNoMatchReason),typeof(Carthago.Engine.Rules.RuleEvaluationResult),typeof(Carthago.Engine.Rules.RuleEvaluationTrace),typeof(Carthago.Engine.Rules.RuleMaturity),typeof(Carthago.Engine.Rules.RuleSignalKind),typeof(Carthago.Engine.Rules.RuleReference),typeof(Carthago.Engine.Rules.RuleTelemetryRequirement),typeof(Carthago.Engine.Rules.RuleFalsePositiveNote),typeof(Carthago.Engine.Rules.RuleIntelligence),typeof(Carthago.Engine.Rules.RuleIntelligenceFactory),typeof(Carthago.Engine.Rules.RulePrecisionMaturity),typeof(Carthago.Engine.Rules.RuleRuntimeMode),typeof(Carthago.Engine.Rules.RuleTelemetryKind),typeof(Carthago.Engine.Rules.RulePrecisionProfile),typeof(Carthago.Engine.Rules.RulePrecisionValidationResult),typeof(Carthago.Engine.Rules.RulePrecisionCatalog),typeof(Carthago.Engine.Rules.ConfidenceBuilder),typeof(Carthago.Engine.Rules.EvidenceBuilder),typeof(Carthago.Engine.Rules.RuleIdValidator)})
            Assert.Same(core,type.Assembly);
        Assert.DoesNotContain(core.GetReferencedAssemblies(),a=>a.Name is "Carthago" or "SharpPcap" or "PacketDotNet" or "PresentationFramework" or "PresentationCore" or "WindowsBase");
    }

    [Fact]
    public void DetectionEventPreservesIdentityAliasesAndDefaultDelivery()
    {
        var evt=new DetectionEvent{RuleId="R001",Summary="fixture",TimestampUtc=Epoch,Severity=SeverityLevel.High};
        Assert.True(Guid.TryParseExact(evt.EventId,"N",out _));
        Assert.Equal("fixture",evt.Description);
        Assert.Equal(Epoch,evt.Timestamp);
        Assert.Equal(DateTimeKind.Utc,evt.TimestampUtc.Kind);
        Assert.Equal(DetectionDeliveryStatus.Pending,evt.DeliveryStatus);
        Assert.Equal(ExternalSinkDeliveryStatus.NotQueued,evt.ExternalDeliveryStatus);
        Assert.Equal(DetectionSuppressionStatus.None,evt.SuppressionStatus);
        Assert.Equal(Sensitivity.Balanced,evt.SensitivityAtTrigger);
        var roundtrip=JsonSerializer.Deserialize<DetectionEvent>(JsonSerializer.Serialize(evt))!;
        Assert.Equal(evt.EventId,roundtrip.EventId);Assert.Equal(evt.TimestampUtc,roundtrip.TimestampUtc);
        Assert.Equal(evt.Severity,roundtrip.Severity);Assert.Equal(evt.Summary,roundtrip.Summary);
    }

    [Fact]
    public void EvaluationResultsKeepMatchSuppressionFailureAndSkipDistinct()
    {
        var evt=new DetectionEvent{RuleId="R001"};
        var matched=RuleEvaluationResult.Match("R001",evt);
        Assert.True(matched.Evaluated);Assert.True(matched.Matched);Assert.Same(evt,Assert.Single(matched.Events));
        var suppressed=RuleEvaluationResult.SuppressedMatch("R001");
        Assert.True(suppressed.Matched);Assert.True(suppressed.Suppressed);Assert.Empty(suppressed.Events);
        var failed=RuleEvaluationResult.FailedRule("R001","fixture");
        Assert.True(failed.Failed);Assert.False(failed.Matched);Assert.Equal("fixture",failed.FailureMessage);
        var skipped=RuleEvaluationResult.SkippedDisabled("R001");
        Assert.True(skipped.Skipped);Assert.False(skipped.Evaluated);
        Assert.Equal(RuleNoMatchReasonCategory.Disabled,Assert.Single(skipped.NoMatchReasons).Category);
    }

    [Fact]
    public void NoMatchReasonsRetainCategoryCodeAndExplicitTimestamp()
    {
        var reason=RuleNoMatchReason.Create(" R001 ",RuleNoMatchReasonCategory.MissingTelemetry," MISSING "," fixture ",Epoch,
            new Dictionary<string,string>{{"field","dns"}});
        Assert.Equal("R001",reason.RuleId);Assert.Equal("MISSING",reason.Code);
        Assert.Equal("fixture",reason.Message);Assert.Equal(Epoch,reason.TimestampUtc);
        Assert.Equal("dns",reason.Details["field"]);
        var result=RuleEvaluationResult.NoMatch("R001",RuleNoMatchReasonCategory.BelowThreshold,"LOW","fixture");
        Assert.True(result.Evaluated);Assert.False(result.Matched);Assert.Empty(result.Events);
        Assert.Equal(RuleNoMatchReasonCategory.BelowThreshold,Assert.Single(result.NoMatchReasons).Category);
    }

    [Fact]
    public void EvidenceBuilderRetainsStructuredLegacyFieldsAndSensitiveMarker()
    {
        var evt=new DetectionEvent{Summary="fixture",Evidence="port=443; observed"};
        EvidenceBuilder.EnsureStructuredEvidence(evt);
        Assert.Equal("fixture",evt.StructuredEvidence!.Summary);
        Assert.Equal("port",evt.StructuredEvidence.Items[0].Key);
        Assert.Equal("443",evt.StructuredEvidence.Items[0].Value);
        EvidenceBuilder.AppendEvidence(evt,"protocol","TLS","fixture");
        Assert.Contains(evt.StructuredEvidence!.Items,x=>x.Key=="protocol"&&x.Value=="TLS");
        var set=EvidenceBuilder.FromLegacyEvidence("fixture",null,new DetectionEvidenceItem("marker","fixture","test",true));
        Assert.True(Assert.Single(set.Items).IsSensitive);
    }

    [Theory]
    [InlineData(0.0,DetectionConfidenceLabel.Unknown)]
    [InlineData(0.44,DetectionConfidenceLabel.Low)]
    [InlineData(0.45,DetectionConfidenceLabel.Medium)]
    [InlineData(0.75,DetectionConfidenceLabel.High)]
    public void ConfidenceLabelsPreserveThresholds(double score,DetectionConfidenceLabel expected)
        => Assert.Equal(expected,ConfidenceBuilder.Label(score));

    [Fact]
    public void ConfidenceClampsNonFiniteAndOutOfRangeScores()
    {
        var evt=new DetectionEvent();
        new ConfidenceBuilder().AddEvidence(double.NaN,"bad").ApplyTo(evt);
        Assert.Equal(0d,evt.ConfidenceScore);Assert.Equal(DetectionConfidenceLabel.Unknown,evt.ConfidenceLabel);
        new ConfidenceBuilder().AddEvidence(2,"fixture").ApplyTo(evt);
        Assert.Equal(1d,evt.ConfidenceScore);Assert.Equal(DetectionConfidenceLabel.High,evt.ConfidenceLabel);
        Assert.NotNull(evt.StructuredEvidence);
    }

    [Fact]
    public void ExistingRuleMetadataAndPrecisionCatalogRemainLinked()
    {
        var descriptor=Descriptor();
        var intelligence=RuleIntelligenceFactory.CreateDefault(descriptor);
        var profile=RulePrecisionCatalog.GetProfile(descriptor);
        Assert.Equal(descriptor.RuleId,intelligence.RuleId);
        Assert.Equal(RuleMaturity.Stable,intelligence.Maturity);
        Assert.NotNull(intelligence.PrecisionProfile);
        Assert.Equal(profile.RuleId,intelligence.PrecisionProfile!.RuleId);
        Assert.Equal(profile.DefaultMode,intelligence.PrecisionProfile.DefaultMode);
        Assert.Equal(RuleMode.Disabled,RulePrecisionCatalog.MostRestrictive(RuleMode.Alert,RuleMode.Disabled));
        Assert.Equal(RuleMode.Shadow,RulePrecisionCatalog.ToRuleMode(RuleRuntimeMode.Shadow));
    }

    [Theory]
    [InlineData("relaxed",Sensitivity.Relaxed,1.5,85)]
    [InlineData("balanced",Sensitivity.Balanced,1.0,75)]
    [InlineData("aggressive",Sensitivity.Aggressive,0.8,60)]
    public void SensitivityPreservesExistingFactors(string input,Sensitivity expected,double factor,int threshold)
    {
        Assert.True(SensitivityExtensions.TryParse(input,out var value));
        Assert.Equal(expected,value);Assert.Equal(factor,value.Factor());Assert.Equal(threshold,value.AbuseIpdbThreshold());
    }

    [Fact]
    public void RuleTraceMaintainsSeparateEvaluationAndDeliveryStages()
    {
        var trace=new RuleEvaluationTrace{PacketId="fixture",TimestampUtc=Epoch};
        trace.EvaluatedRuleIds.Add("R001");trace.MatchedRuleIds.Add("R001");
        Assert.Empty(trace.EmittedRuleIds);Assert.Empty(trace.PersistedEventIds);
        trace.FailedToPersistEventIds.Add("fixture-event");
        Assert.Empty(trace.PersistedEventIds);Assert.Single(trace.FailedToPersistEventIds);
    }

    [Theory]
    [InlineData("R001",true)]
    [InlineData("R999",true)]
    [InlineData("R1000",true)]
    [InlineData("R1001",true)]
    [InlineData("R000",false)]
    [InlineData("R0999",false)]
    [InlineData("r001",false)]
    [InlineData("R1",false)]
    public void RuleIdValidationPreservesCurrentContract(string value,bool valid)
        => Assert.Equal(valid,RuleIdValidator.IsValid(value));
}
