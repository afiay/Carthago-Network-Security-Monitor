// SPDX-License-Identifier: MIT
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;
public sealed class PortableDetectionContractCompatibilityTests
{
    [Fact]
    public void FormerWindowsAssemblyForwardsAllRelocatedContractTypes()
    {
        var legacy=typeof(PacketHandler).Assembly;
        foreach(var type in new[]{typeof(Carthago.Models.SeverityLevel),typeof(Carthago.Models.DetectionDeliveryStatus),typeof(Carthago.Models.DetectionSuppressionStatus),typeof(Carthago.Models.DetectionConfidenceLabel),typeof(Carthago.Models.DetectionEvidenceItem),typeof(Carthago.Models.DetectionEvidenceSet),typeof(Carthago.Models.ExternalSinkDeliveryStatus),typeof(Carthago.Models.DetectionEvent),typeof(Carthago.Models.Sensitivity),typeof(Carthago.Models.SensitivityExtensions),typeof(Carthago.Engine.Rules.RuleDescriptor),typeof(Carthago.Engine.Rules.RuleMode),typeof(Carthago.Engine.Rules.RuleNoMatchReasonCategory),typeof(Carthago.Engine.Rules.RuleNoMatchReason),typeof(Carthago.Engine.Rules.RuleEvaluationResult),typeof(Carthago.Engine.Rules.RuleEvaluationTrace),typeof(Carthago.Engine.Rules.RuleMaturity),typeof(Carthago.Engine.Rules.RuleSignalKind),typeof(Carthago.Engine.Rules.RuleReference),typeof(Carthago.Engine.Rules.RuleTelemetryRequirement),typeof(Carthago.Engine.Rules.RuleFalsePositiveNote),typeof(Carthago.Engine.Rules.RuleIntelligence),typeof(Carthago.Engine.Rules.RuleIntelligenceFactory),typeof(Carthago.Engine.Rules.RulePrecisionMaturity),typeof(Carthago.Engine.Rules.RuleRuntimeMode),typeof(Carthago.Engine.Rules.RuleTelemetryKind),typeof(Carthago.Engine.Rules.RulePrecisionProfile),typeof(Carthago.Engine.Rules.RulePrecisionValidationResult),typeof(Carthago.Engine.Rules.RulePrecisionCatalog),typeof(Carthago.Engine.Rules.ConfidenceBuilder),typeof(Carthago.Engine.Rules.EvidenceBuilder),typeof(Carthago.Engine.Rules.RuleIdValidator)})
        {
            Assert.Contains(type,legacy.GetForwardedTypes());
            Assert.Same(type,Type.GetType(type.FullName+", "+legacy.GetName().Name,throwOnError:true));
        }
    }
}
