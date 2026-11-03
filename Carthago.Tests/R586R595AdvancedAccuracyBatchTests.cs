// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; 0 tests executed.
using System;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Catalog;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R586R595AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 3, 12, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R586", "R587", "R588", "R589", "R590", "R591", "R592", "R593", "R594", "R595" };

    private static IDetectionRule Rule(string id) => id switch
    {
            "R586" => new R586_Wp2ShellPluginAccessRequestRule(),
            "R587" => new R587_ScreenConnectSetupWizardPathRequestRule(),
            "R588" => new R588_SolarWindsSupernovaHandlerRequestRule(),
            "R589" => new R589_WebLogicKeystoreScriptRequestRule(),
            "R590" => new R590_RejettoHfsSearchPayloadRequestRule(),
            "R591" => new R591_AdSelfServiceSuspiciousEndpointRequestRule(),
            "R592" => new R592_DewmodeWebshellQueryRequestRule(),
            "R593" => new R593_ApacheSparkDoAsBacktickRequestRule(),
            "R594" => new R594_BitbucketArchiveExecPrefixRequestRule(),
            "R595" => new R595_GrafanaPluginTraversalRequestRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static TrafficRecord Request(string method, string uri)
        => new()
        {
            Id = Guid.NewGuid(), Source = "10.10.1.20", Destination = "10.10.1.30",
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 50221, DestinationPort = 8080, Length = 240, L4Len = 180,
            ApplicationProtocol = "HTTP", HttpMethod = method,
            HttpUri = uri, HttpHost = "web.test.internal"
        };

    private static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    [Theory]
        [InlineData("R586", "GET", "/wp-content/plugins/wp2shell_ab12/shell.php")]
        [InlineData("R587", "GET", "/SetupWizard.aspx/bypass")]
        [InlineData("R588", "GET", "/Orion/LogoImageHandler.ashx?clazz=System.String")]
        [InlineData("R589", "GET", "/config/keystore/check.jsp")]
        [InlineData("R590", "GET", "/?search=%00{.exec|cmd.exe.")]
        [InlineData("R591", "GET", "/ServletApi/../RestApi/LogonCustomization")]
        [InlineData("R592", "GET", "/main.html?dwn=payload&fn=report")]
        [InlineData("R593", "GET", "/jobs?doAs=`whoami`")]
        [InlineData("R594", "GET", "/rest/api/latest/projects/A/repos/B/archive?prefix=a%00--exec")]
        [InlineData("R595", "GET", "/public/plugins/live/../../../../../../../etc/passwd")]
    public async Task IndependentPositiveRequestSignatureMatches(string id, string method, string uri)
    {
        var result = await Rule(id).EvaluateAsync(At(Request(method, uri)));
        Assert.True(result.Matched);
        Assert.Equal(id, Assert.Single(result.Events).RuleId);
    }

    [Theory]
        [InlineData("R586", "GET", "/wp-content/plugins/legitimate/shell.php")]
        [InlineData("R587", "GET", "/SetupWizard.aspx")]
        [InlineData("R588", "GET", "/Orion/LogoImageHandler.ashx?size=1")]
        [InlineData("R589", "GET", "/config/keystore/check.png")]
        [InlineData("R590", "GET", "/?search=normal")]
        [InlineData("R591", "GET", "/ServletApi/RestApi/LogonCustomization")]
        [InlineData("R592", "GET", "/main.html?fn=report")]
        [InlineData("R593", "GET", "/jobs?doAs=guest")]
        [InlineData("R594", "GET", "/rest/api/latest/projects/A/repos/B/archive?prefix=normal")]
        [InlineData("R595", "GET", "/public/plugins/live/index.html")]
    public async Task BenignNearMissNeverMatches(string id, string method, string uri)
        => Assert.False((await Rule(id).EvaluateAsync(At(Request(method, uri)))).Matched);

    [Theory]
        [InlineData("R586", "GET", "/wp-content/plugins/wp2shell_ab12/shell.php")]
        [InlineData("R587", "GET", "/SetupWizard.aspx/bypass")]
        [InlineData("R588", "GET", "/Orion/LogoImageHandler.ashx?clazz=System.String")]
        [InlineData("R589", "GET", "/config/keystore/check.jsp")]
        [InlineData("R590", "GET", "/?search=%00{.exec|cmd.exe.")]
        [InlineData("R591", "GET", "/ServletApi/../RestApi/LogonCustomization")]
        [InlineData("R592", "GET", "/main.html?dwn=payload&fn=report")]
        [InlineData("R593", "GET", "/jobs?doAs=`whoami`")]
        [InlineData("R594", "GET", "/rest/api/latest/projects/A/repos/B/archive?prefix=a%00--exec")]
        [InlineData("R595", "GET", "/public/plugins/live/../../../../../../../etc/passwd")]
    public async Task MissingContradictoryAndInfoOnlyProvenanceRejected(string id, string method, string uri)
    {
        var rule = Rule(id);
        var missing = Request(method, uri); missing.ApplicationProtocol = null;
        var tls = Request(method, uri); tls.TlsVersion = "TLS1.3";
        var info = Request(method, "/ordinary"); info.Info = uri;
        var udp = Request(method, uri); udp.IsTcp = false; udp.IsUdp = true;
        var dns = Request(method, uri); dns.DnsQname = "inconsistent.test";
        Assert.False((await rule.EvaluateAsync(At(missing))).Matched);
        Assert.False((await rule.EvaluateAsync(At(tls, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(info, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(udp, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 4))).Matched);
    }

    [Theory]
        [InlineData("R586", "GET", "/wp-content/plugins/wp2shell_ab12/shell.php")]
        [InlineData("R587", "GET", "/SetupWizard.aspx/bypass")]
        [InlineData("R588", "GET", "/Orion/LogoImageHandler.ashx?clazz=System.String")]
        [InlineData("R589", "GET", "/config/keystore/check.jsp")]
        [InlineData("R590", "GET", "/?search=%00{.exec|cmd.exe.")]
        [InlineData("R591", "GET", "/ServletApi/../RestApi/LogonCustomization")]
        [InlineData("R592", "GET", "/main.html?dwn=payload&fn=report")]
        [InlineData("R593", "GET", "/jobs?doAs=`whoami`")]
        [InlineData("R594", "GET", "/rest/api/latest/projects/A/repos/B/archive?prefix=a%00--exec")]
        [InlineData("R595", "GET", "/public/plugins/live/../../../../../../../etc/passwd")]
    public async Task DuplicateOutOfOrderAndCooldownAreBounded(string id, string method, string uri)
    {
        var rule = Rule(id);
        var first = Request(method, uri);
        Assert.True((await rule.EvaluateAsync(At(first, 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first, 11))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request(method, uri), 9))).Matched);
        var repeated = await rule.EvaluateAsync(At(Request(method, uri), 12));
        Assert.Empty(repeated.Events);
        Assert.True(repeated.Suppressed);
        Assert.True((await rule.EvaluateAsync(At(Request(method, uri), 610))).Matched);
    }

    [Theory]
        [InlineData("R586", "GET", "/wp-content/plugins/wp2shell_ab12/shell.php")]
        [InlineData("R587", "GET", "/SetupWizard.aspx/bypass")]
        [InlineData("R588", "GET", "/Orion/LogoImageHandler.ashx?clazz=System.String")]
        [InlineData("R589", "GET", "/config/keystore/check.jsp")]
        [InlineData("R590", "GET", "/?search=%00{.exec|cmd.exe.")]
        [InlineData("R591", "GET", "/ServletApi/../RestApi/LogonCustomization")]
        [InlineData("R592", "GET", "/main.html?dwn=payload&fn=report")]
        [InlineData("R593", "GET", "/jobs?doAs=`whoami`")]
        [InlineData("R594", "GET", "/rest/api/latest/projects/A/repos/B/archive?prefix=a%00--exec")]
        [InlineData("R595", "GET", "/public/plugins/live/../../../../../../../etc/passwd")]
    public async Task EventEvidenceDoesNotContainRawQueryOrExploitSuccessClaim(string id, string method, string uri)
    {
        var evt = Assert.Single((await Rule(id).EvaluateAsync(At(Request(method, uri)))).Events);
        var serialized = JsonSerializer.Serialize(evt);
        Assert.DoesNotContain(uri, serialized);
        Assert.Contains("request_only_unknown", serialized);
        Assert.DoesNotContain("successful exploitation", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
        [InlineData("R586", "GET", "/wp-content/plugins/wp2shell_ab12/shell.php")]
        [InlineData("R587", "GET", "/SetupWizard.aspx/bypass")]
        [InlineData("R588", "GET", "/Orion/LogoImageHandler.ashx?clazz=System.String")]
        [InlineData("R589", "GET", "/config/keystore/check.jsp")]
        [InlineData("R590", "GET", "/?search=%00{.exec|cmd.exe.")]
        [InlineData("R591", "GET", "/ServletApi/../RestApi/LogonCustomization")]
        [InlineData("R592", "GET", "/main.html?dwn=payload&fn=report")]
        [InlineData("R593", "GET", "/jobs?doAs=`whoami`")]
        [InlineData("R594", "GET", "/rest/api/latest/projects/A/repos/B/archive?prefix=a%00--exec")]
        [InlineData("R595", "GET", "/public/plugins/live/../../../../../../../etc/passwd")]
    public async Task WrongMethodOrMalformedRequestDoesNotMatch(string id, string method, string uri)
    {
        var rule = Rule(id);
        var wrongMethod = Request("DELETE", uri);
        var noSource = Request(method, uri); noSource.Source = null;
        var oversize = Request(method, "/" + new string('a', 1025) + uri);
        var badId = Request(method, uri); badId.Id = Guid.Empty;
        Assert.False((await rule.EvaluateAsync(At(wrongMethod))).Matched);
        Assert.False((await rule.EvaluateAsync(At(noSource, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(oversize, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(badId, 3))).Matched);
    }

    [Fact]
    public void EveryRuleMustBeIndependentlyRegisteredInShadowMode()
    {
        var registry = RuleRegistry.CreateDefaultRules();
        foreach (var id in Ids)
        {
            var rule = Assert.Single(registry.Where(x => x.Descriptor.RuleId == id));
            var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule);
            Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
        }
        Assert.Equal(Ids.Length, registry.Count(r => Ids.Contains(r.Descriptor.RuleId)));
    }
}
