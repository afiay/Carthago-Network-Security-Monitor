// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; synthetic, no test execution authorized.
using System;
using System.Reflection;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Carthago.Tests.ProtocolIntelligence;
using Xunit;

namespace Carthago.Tests;

public sealed class R286R485ShadowEnginePreparationTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task EngineEventPreparationPreservesCaptureCandidateShadowEvenWithAlertProfile(bool ldap)
    {
        IDetectionRule rule = ldap
            ? new R286_LDAPSimpleBindOverCleartextExternalRule()
            : new R485_BACnetWritePropertyRequestRule();
        var record = ldap
            ? LdapSimpleBindCaptureIntegrationTests.Parse(
                LdapSimpleBindCaptureIntegrationTests.Bind(), sourceOverride: "203.0.113.118")
            : BacnetWritePrecisionTests.Parse(
                BacnetWritePropertyInspectorTests.Request(), sourceOverride: "203.0.113.119");
        var result = await rule.EvaluateAsync(
            new RuleEvaluationContext(record, Sensitivity.Balanced, DateTime.UtcNow));
        var evt = Assert.Single(result.Events);
        Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus);

        // Invoke the real RuleEngine preparation gate, which historically
        // resets Suppressed -> None but explicitly preserves Shadowed.
        var preparation = typeof(RuleEngine).GetMethod("PrepareDetectionEvent",
            BindingFlags.Static | BindingFlags.NonPublic);
        Assert.NotNull(preparation);
        preparation!.Invoke(null, new object[] {
            evt, rule.Descriptor, record, Sensitivity.Balanced, DateTime.UtcNow
        });
        Assert.Equal(DetectionSuppressionStatus.Shadowed, evt.SuppressionStatus);
    }
}
