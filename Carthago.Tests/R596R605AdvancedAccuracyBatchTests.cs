// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED: xUnit authored; no test or build execution.
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

public sealed class R596R605AdvancedAccuracyBatchTests
{
    private static readonly DateTime Origin = new(2026, 11, 3, 13, 0, 0, DateTimeKind.Utc);
    private static readonly string[] Ids = { "R596", "R597", "R598", "R599", "R600", "R601", "R602", "R603", "R604", "R605" };

    private static IDetectionRule Rule(string id) => id switch
    {
            "R596" => new R596_SonicWallJarrewriteAbuseRequestRule(),
            "R597" => new R597_ModxTvsClassKeyTraversalRequestRule(),
            "R598" => new R598_WindowsLocalPathInHttpQueryRule(),
            "R599" => new R599_ArcadyanAbstractConfigTraversalRequestRule(),
            "R600" => new R600_ExchangeHafniumThemesResourcePostRequestRule(),
            "R601" => new R601_ReGeorgHeaderlessControlQueryRequestRule(),
            "R602" => new R602_SolarWindsOrionResourceAuthBypassRequestRule(),
            "R603" => new R603_WebLogicJndiBindingLdapRequestRule(),
            "R604" => new R604_ExchangeViewStateQueryRequestRule(),
            "R605" => new R605_ConfluenceUploadFilenameTraversalRequestRule(),
        _ => throw new ArgumentOutOfRangeException(nameof(id))
    };

    private static TrafficRecord Request(string method, string uri, string agent, string headers)
        => new()
        {
            Id = Guid.NewGuid(), Source = "10.10.1.20", Destination = "10.10.1.30",
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 50221, DestinationPort = 8080, Length = 512, L4Len = 400,
            ApplicationProtocol = "HTTP", HttpMethod = method,
            HttpUri = uri, HttpUserAgent = agent, HttpRequestHeaders = headers,
            HttpHost = "web.lab.internal"
        };

    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    [Theory]
    [InlineData("R596", "GET", "/cgi-bin/jarrewrite.sh?handler=update", "() { :;}; /bin/bash -c id", "Host: edge.local")]
    [InlineData("R597", "GET", "/manager/controllers/default/resource/tvs.php?class_key=../../../../../../windows/win.ini%00", "curl/8.0", "Host: cms.local")]
    [InlineData("R598", "GET", "/download?file=C:/Windows/System32/config/SAM", "curl/8.0", "Host: app.local")]
    [InlineData("R599", "GET", "/apply_abstract.cgi?cfg=..%2f..%2fetc%2fpasswd", "curl/8.0", "Host: router.local")]
    [InlineData("R600", "POST", "/owa/auth/Current/themes/resources/update.aspx", "curl/8.0", "Host: mail.local")]
    [InlineData("R601", "POST", "/tunnel.jsp?cmd=connect&target=10.0.0.12", "", "Host: proxy.local")]
    [InlineData("R602", "GET", "/SolarWinds/api/WebResource.axd?x=one", "curl/8.0", "Host: orion.local")]
    [InlineData("R603", "GET", "/console/jndi?handle=com.bea.console.handles.JndiBindingHandle&url=ldap://example.local:1389/a&server=AdminServer", "curl/8.0", "Host: weblogic.local")]
    [InlineData("R604", "GET", "/ecp/default.aspx?__VIEWSTATE=redacted", "curl/8.0", "Host: exchange.local")]
    [InlineData("R605", "POST", "/plugins/servlet/upload.action?filename=../../../../../../x.jsp", "curl/8.0", "Host: wiki.local")]
    public async Task ExactIndependentSignatureMatches(string id, string method, string uri, string agent, string headers)
    {
        var result = await Rule(id).EvaluateAsync(At(Request(method, uri, agent, headers)));
        Assert.True(result.Matched);
        Assert.Equal(id, Assert.Single(result.Events).RuleId);
    }

    [Theory]
    [InlineData("R596", "GET", "/cgi-bin/jarrewrite.sh?handler=update", "Mozilla/5.0", "Host: edge.local")]
    [InlineData("R597", "GET", "/manager/controllers/default/resource/tvs.php?class_key=normal", "curl/8.0", "Host: cms.local")]
    [InlineData("R598", "GET", "/download?file=/var/log/app.log", "curl/8.0", "Host: app.local")]
    [InlineData("R599", "GET", "/apply_abstract.cgi?cfg=trusted", "curl/8.0", "Host: router.local")]
    [InlineData("R600", "POST", "/owa/auth/Current/themes/logo.png", "curl/8.0", "Host: mail.local")]
    [InlineData("R601", "POST", "/tunnel.jsp?cmd=connect&target=10.0.0.12", "Mozilla/5.0", "Host: proxy.local")]
    [InlineData("R602", "GET", "/SolarWinds/api/Orion/Skipi18n/Profiler/index.html", "curl/8.0", "Host: orion.local")]
    [InlineData("R603", "GET", "/console/jndi?handle=com.bea.console.handles.JndiBindingHandle&server=AdminServer", "curl/8.0", "Host: weblogic.local")]
    [InlineData("R604", "GET", "/ecp/default.aspx?ref=normal", "curl/8.0", "Host: exchange.local")]
    [InlineData("R605", "POST", "/plugins/servlet/upload.action?filename=report.pdf", "curl/8.0", "Host: wiki.local")]
    public async Task BenignNearMissDoesNotMatch(string id, string method, string uri, string agent, string headers)
    {
        Assert.False((await Rule(id).EvaluateAsync(At(Request(method, uri, agent, headers)))).Matched);
    }

    [Theory]
    [InlineData("R596", "GET", "/cgi-bin/jarrewrite.sh?handler=update", "() { :;}; /bin/bash -c id", "Host: edge.local")]
    [InlineData("R597", "GET", "/manager/controllers/default/resource/tvs.php?class_key=../../../../../../windows/win.ini%00", "curl/8.0", "Host: cms.local")]
    [InlineData("R598", "GET", "/download?file=C:/Windows/System32/config/SAM", "curl/8.0", "Host: app.local")]
    [InlineData("R599", "GET", "/apply_abstract.cgi?cfg=..%2f..%2fetc%2fpasswd", "curl/8.0", "Host: router.local")]
    [InlineData("R600", "POST", "/owa/auth/Current/themes/resources/update.aspx", "curl/8.0", "Host: mail.local")]
    [InlineData("R601", "POST", "/tunnel.jsp?cmd=connect&target=10.0.0.12", "", "Host: proxy.local")]
    [InlineData("R602", "GET", "/SolarWinds/api/WebResource.axd?x=one", "curl/8.0", "Host: orion.local")]
    [InlineData("R603", "GET", "/console/jndi?handle=com.bea.console.handles.JndiBindingHandle&url=ldap://example.local:1389/a&server=AdminServer", "curl/8.0", "Host: weblogic.local")]
    [InlineData("R604", "GET", "/ecp/default.aspx?__VIEWSTATE=redacted", "curl/8.0", "Host: exchange.local")]
    [InlineData("R605", "POST", "/plugins/servlet/upload.action?filename=../../../../../../x.jsp", "curl/8.0", "Host: wiki.local")]
    public async Task WrongMethodAndMissingParserFieldsFailClosed(string id, string method, string uri, string agent, string headers)
    {
        var rule = Rule(id);
        var wrongMethod = Request(method == "POST" ? "GET" : "DELETE", uri, agent, headers);
        var absent = Request(method, uri, agent, headers); absent.ApplicationProtocol = null;
        var infoOnly = Request(method, "/safe", agent, headers); infoOnly.Info = uri;
        var missingIp = Request(method, uri, agent, headers); missingIp.Source = null;
        Assert.False((await rule.EvaluateAsync(At(wrongMethod))).Matched);
        Assert.False((await rule.EvaluateAsync(At(absent, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(infoOnly, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(missingIp, 3))).Matched);
    }

    [Theory]
    [InlineData("R596", "GET", "/cgi-bin/jarrewrite.sh?handler=update", "() { :;}; /bin/bash -c id", "Host: edge.local")]
    [InlineData("R597", "GET", "/manager/controllers/default/resource/tvs.php?class_key=../../../../../../windows/win.ini%00", "curl/8.0", "Host: cms.local")]
    [InlineData("R598", "GET", "/download?file=C:/Windows/System32/config/SAM", "curl/8.0", "Host: app.local")]
    [InlineData("R599", "GET", "/apply_abstract.cgi?cfg=..%2f..%2fetc%2fpasswd", "curl/8.0", "Host: router.local")]
    [InlineData("R600", "POST", "/owa/auth/Current/themes/resources/update.aspx", "curl/8.0", "Host: mail.local")]
    [InlineData("R601", "POST", "/tunnel.jsp?cmd=connect&target=10.0.0.12", "", "Host: proxy.local")]
    [InlineData("R602", "GET", "/SolarWinds/api/WebResource.axd?x=one", "curl/8.0", "Host: orion.local")]
    [InlineData("R603", "GET", "/console/jndi?handle=com.bea.console.handles.JndiBindingHandle&url=ldap://example.local:1389/a&server=AdminServer", "curl/8.0", "Host: weblogic.local")]
    [InlineData("R604", "GET", "/ecp/default.aspx?__VIEWSTATE=redacted", "curl/8.0", "Host: exchange.local")]
    [InlineData("R605", "POST", "/plugins/servlet/upload.action?filename=../../../../../../x.jsp", "curl/8.0", "Host: wiki.local")]
    public async Task ConflictingTransportAndSpoofedMetadataFailClosed(string id, string method, string uri, string agent, string headers)
    {
        var rule = Rule(id);
        var tls = Request(method, uri, agent, headers); tls.TlsVersion = "TLS1.3";
        var dns = Request(method, uri, agent, headers); dns.DnsQname = "not-this-request.example";
        var redis = Request(method, uri, agent, headers); redis.RedisRespConfigSetRequestObserved = true;
        var udp = Request(method, uri, agent, headers); udp.IsTcp = false; udp.IsUdp = true;
        var quic = Request(method, uri, agent, headers); quic.IsQuic = true;
        Assert.False((await rule.EvaluateAsync(At(tls))).Matched);
        Assert.False((await rule.EvaluateAsync(At(dns, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(redis, 2))).Matched);
        Assert.False((await rule.EvaluateAsync(At(udp, 3))).Matched);
        Assert.False((await rule.EvaluateAsync(At(quic, 4))).Matched);
    }

    [Theory]
    [InlineData("R596", "GET", "/cgi-bin/jarrewrite.sh?handler=update", "() { :;}; /bin/bash -c id", "Host: edge.local")]
    [InlineData("R597", "GET", "/manager/controllers/default/resource/tvs.php?class_key=../../../../../../windows/win.ini%00", "curl/8.0", "Host: cms.local")]
    [InlineData("R598", "GET", "/download?file=C:/Windows/System32/config/SAM", "curl/8.0", "Host: app.local")]
    [InlineData("R599", "GET", "/apply_abstract.cgi?cfg=..%2f..%2fetc%2fpasswd", "curl/8.0", "Host: router.local")]
    [InlineData("R600", "POST", "/owa/auth/Current/themes/resources/update.aspx", "curl/8.0", "Host: mail.local")]
    [InlineData("R601", "POST", "/tunnel.jsp?cmd=connect&target=10.0.0.12", "", "Host: proxy.local")]
    [InlineData("R602", "GET", "/SolarWinds/api/WebResource.axd?x=one", "curl/8.0", "Host: orion.local")]
    [InlineData("R603", "GET", "/console/jndi?handle=com.bea.console.handles.JndiBindingHandle&url=ldap://example.local:1389/a&server=AdminServer", "curl/8.0", "Host: weblogic.local")]
    [InlineData("R604", "GET", "/ecp/default.aspx?__VIEWSTATE=redacted", "curl/8.0", "Host: exchange.local")]
    [InlineData("R605", "POST", "/plugins/servlet/upload.action?filename=../../../../../../x.jsp", "curl/8.0", "Host: wiki.local")]
    public async Task DuplicateIdOutOfOrderAndCooldownSuppressesSubsequentAlerts(string id, string method, string uri, string agent, string headers)
    {
        var rule = Rule(id);
        var first = Request(method, uri, agent, headers);
        Assert.True((await rule.EvaluateAsync(At(first, 10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first, 11))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Request(method, uri, agent, headers), 9))).Matched);
        var cooldown = await rule.EvaluateAsync(At(Request(method, uri, agent, headers), 12));
        Assert.True(cooldown.Suppressed);
        Assert.Empty(cooldown.Events);
        Assert.True((await rule.EvaluateAsync(At(Request(method, uri, agent, headers), 611))).Matched);
    }

    [Theory]
    [InlineData("R596", "GET", "/cgi-bin/jarrewrite.sh?handler=update", "() { :;}; /bin/bash -c id", "Host: edge.local")]
    [InlineData("R597", "GET", "/manager/controllers/default/resource/tvs.php?class_key=../../../../../../windows/win.ini%00", "curl/8.0", "Host: cms.local")]
    [InlineData("R598", "GET", "/download?file=C:/Windows/System32/config/SAM", "curl/8.0", "Host: app.local")]
    [InlineData("R599", "GET", "/apply_abstract.cgi?cfg=..%2f..%2fetc%2fpasswd", "curl/8.0", "Host: router.local")]
    [InlineData("R600", "POST", "/owa/auth/Current/themes/resources/update.aspx", "curl/8.0", "Host: mail.local")]
    [InlineData("R601", "POST", "/tunnel.jsp?cmd=connect&target=10.0.0.12", "", "Host: proxy.local")]
    [InlineData("R602", "GET", "/SolarWinds/api/WebResource.axd?x=one", "curl/8.0", "Host: orion.local")]
    [InlineData("R603", "GET", "/console/jndi?handle=com.bea.console.handles.JndiBindingHandle&url=ldap://example.local:1389/a&server=AdminServer", "curl/8.0", "Host: weblogic.local")]
    [InlineData("R604", "GET", "/ecp/default.aspx?__VIEWSTATE=redacted", "curl/8.0", "Host: exchange.local")]
    [InlineData("R605", "POST", "/plugins/servlet/upload.action?filename=../../../../../../x.jsp", "curl/8.0", "Host: wiki.local")]
    public async Task RawUrlAndPotentiallySensitiveParametersAreAbsentFromEvidence(string id, string method, string uri, string agent, string headers)
    {
        var evt = Assert.Single((await Rule(id).EvaluateAsync(At(Request(method, uri, agent, headers)))).Events);
        var serialized = JsonSerializer.Serialize(evt);
        Assert.DoesNotContain(uri, serialized);
        Assert.Contains("request_only_unknown", serialized);
        Assert.DoesNotContain("successful exploitation", serialized, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("R596", "GET", "/cgi-bin/jarrewrite.sh?handler=update", "() { :;}; /bin/bash -c id", "Host: edge.local")]
    [InlineData("R597", "GET", "/manager/controllers/default/resource/tvs.php?class_key=../../../../../../windows/win.ini%00", "curl/8.0", "Host: cms.local")]
    [InlineData("R598", "GET", "/download?file=C:/Windows/System32/config/SAM", "curl/8.0", "Host: app.local")]
    [InlineData("R599", "GET", "/apply_abstract.cgi?cfg=..%2f..%2fetc%2fpasswd", "curl/8.0", "Host: router.local")]
    [InlineData("R600", "POST", "/owa/auth/Current/themes/resources/update.aspx", "curl/8.0", "Host: mail.local")]
    [InlineData("R601", "POST", "/tunnel.jsp?cmd=connect&target=10.0.0.12", "", "Host: proxy.local")]
    [InlineData("R602", "GET", "/SolarWinds/api/WebResource.axd?x=one", "curl/8.0", "Host: orion.local")]
    [InlineData("R603", "GET", "/console/jndi?handle=com.bea.console.handles.JndiBindingHandle&url=ldap://example.local:1389/a&server=AdminServer", "curl/8.0", "Host: weblogic.local")]
    [InlineData("R604", "GET", "/ecp/default.aspx?__VIEWSTATE=redacted", "curl/8.0", "Host: exchange.local")]
    [InlineData("R605", "POST", "/plugins/servlet/upload.action?filename=../../../../../../x.jsp", "curl/8.0", "Host: wiki.local")]
    public async Task InvalidIdsAndOversizeRequestsAreRejected(string id, string method, string uri, string agent, string headers)
    {
        var rule = Rule(id);
        var invalidId = Request(method, uri, agent, headers); invalidId.Id = Guid.Empty;
        var oversized = Request(method, "/" + new string('z', 1025) + uri, agent, headers);
        var malformed = Request(method, uri + "\r\nExploit: x", agent, headers);
        Assert.False((await rule.EvaluateAsync(At(invalidId))).Matched);
        Assert.False((await rule.EvaluateAsync(At(oversized, 1))).Matched);
        Assert.False((await rule.EvaluateAsync(At(malformed, 2))).Matched);
    }

    [Fact]
    public async Task ReGeorgMissingHeaderSummaryFailsClosed()
    {
        var rule = Rule("R601");
        var r = Request("POST", "/tunnel.jsp?cmd=read", "", "Host: proxy.local");
        r.HttpRequestHeaders = null;
        Assert.False((await rule.EvaluateAsync(At(r))).Matched);
    }

    [Fact]
    public async Task ReGeorgRefererIsBenignNegative()
    {
        var r = Request("POST", "/tunnel.jsp?cmd=read", "", "Host: proxy.local\nReferer: https://proxy.local/");
        Assert.False((await Rule("R601").EvaluateAsync(At(r))).Matched);
    }

    [Fact]
    public async Task SolarWindsKnownProfilerPathExcluded()
    {
        var r = Request("GET", "/SolarWinds/api/Orion/Skipi18n/Profiler/WebResource.axd", "curl/8.0", "Host: orion.local");
        Assert.False((await Rule("R602").EvaluateAsync(At(r))).Matched);
    }

    [Fact]
    public void RegistryContainsTenDistinctNewIdsWithoutConvergence()
    {
        var all = RuleRegistry.CreateDefaultRules();
        foreach (var id in Ids)
        {
            var rule = Assert.Single(all.Where(r => r.Descriptor.RuleId == id));
            var precision = Assert.IsAssignableFrom<PrecisionTelemetryDetectionRuleBase>(rule);
            Assert.Equal(RulePrecisionMaturity.Candidate, precision.PrecisionProfile.Maturity);
            Assert.Equal(RuleRuntimeMode.Shadow, precision.PrecisionProfile.DefaultMode);
            Assert.True(precision.PrecisionProfile.MinimumConfidence >= 84);
        }
        Assert.Equal(Ids.Length, all.Count(r => Ids.Contains(r.Descriptor.RuleId)));
    }
}
