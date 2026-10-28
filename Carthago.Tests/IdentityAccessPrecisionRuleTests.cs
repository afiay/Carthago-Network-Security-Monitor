using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class IdentityAccessPrecisionRuleTests
{
    public static IEnumerable<object[]> PrecisionIdentityRules()
    {
        yield return new object[] { new R123_SuspiciousVpnLoginPathRule() };
        yield return new object[] { new R124_ExternalRdpExposureAttemptRule() };
        yield return new object[] { new R125_ExternalWinrmExposureAttemptRule() };
        yield return new object[] { new R126_ExternalSshBruteCandidateRule() };
        yield return new object[] { new R127_AdminPortalAccessFromInternetRule() };
        yield return new object[] { new R128_NetworkApplianceManagementExposureRule() };
        yield return new object[] { new R129_SuspiciousSamlOidcCallbackTrafficRule() };
        yield return new object[] { new R130_CredentialStuffingAgainstWebLoginRule() };
        yield return new object[] { new R131_HttpAuthenticationFailureSpikeRule() };
        yield return new object[] { new R132_RapidCountryChangeForSourceIdentityRule() };
        yield return new object[] { new R133_BasicAuthenticationOverCleartextRule() };
        yield return new object[] { new R134_ApiTokenInUrlQueryRule() };
        yield return new object[] { new R135_BearerTokenOverCleartextHttpRule() };
        yield return new object[] { new R136_SessionCookieOverCleartextHttpRule() };
        yield return new object[] { new R137_PasswordResetOrEnrollmentSpikeRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionIdentityRules))]
    public async Task Precision_identity_access_rules_return_no_match_without_context(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.10.0.10",
            Destination = "10.10.0.20",
            DestinationPort = 9000,
            Protocol = "TCP",
            IsTcp = true,
            Length = 512
        }));

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Theory]
    [MemberData(nameof(PrecisionIdentityRules))]
    public async Task Precision_identity_access_rules_ignore_anytext_only_inputs(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.10.0.11",
            Destination = "203.0.113.11",
            DestinationPort = 9000,
            Protocol = "TCP",
            IsTcp = true,
            Info = "vpn login rdp winrm ssh callback bearer basic session cookie token reset mfa admin",
            Length = 1024
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R123_matches_external_vpn_login_path()
    {
        var rule = new R123_SuspiciousVpnLoginPathRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.5",
            destination: "198.51.100.20",
            destinationPort: 443,
            host: "vpn.example.com",
            method: "GET",
            uri: "/remote/login?realm=saml",
            headers: "Host: vpn.example.com",
            info: "vpn portal login oauth",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R123", SeverityLevel.High, 0.70);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R123_ignores_generic_cloud_login_page()
    {
        var rule = new R123_SuspiciousVpnLoginPathRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.6",
            destination: "198.51.100.21",
            destinationPort: 443,
            host: "login.microsoftonline.com",
            method: "GET",
            uri: "/login",
            headers: "Host: login.microsoftonline.com",
            info: "signin oauth",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R124_matches_cross_boundary_rdp()
    {
        var rule = new R124_ExternalRdpExposureAttemptRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTcpRecord(
            source: "10.0.0.10",
            destination: "198.51.100.30",
            destinationPort: 3389,
            protocol: "TCP",
            service: "RDP",
            info: "mstsc remote desktop session",
            process: "mstsc.exe")));

        var evt = AssertSingleEvent(result, "R124", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "matched_conditions", "network.destinationPort");
    }

    [Fact]
    public async Task R124_ignores_internal_only_rdp()
    {
        var rule = new R124_ExternalRdpExposureAttemptRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTcpRecord(
            source: "10.0.0.11",
            destination: "10.0.0.12",
            destinationPort: 3389,
            protocol: "TCP",
            service: "RDP",
            info: "mstsc remote desktop session",
            process: "mstsc.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R125_matches_cross_boundary_winrm()
    {
        var rule = new R125_ExternalWinrmExposureAttemptRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTcpRecord(
            source: "10.0.0.15",
            destination: "198.51.100.35",
            destinationPort: 5986,
            protocol: "TCP",
            service: "WSMAN",
            info: "winrm powershell remoting",
            process: "pwsh.exe")));

        var evt = AssertSingleEvent(result, "R125", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "matched_conditions", "network.destinationPort");
    }

    [Fact]
    public async Task R125_ignores_internal_only_winrm()
    {
        var rule = new R125_ExternalWinrmExposureAttemptRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTcpRecord(
            source: "10.0.0.16",
            destination: "10.0.0.17",
            destinationPort: 5985,
            protocol: "TCP",
            service: "WSMAN",
            info: "winrm powershell remoting",
            process: "pwsh.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R126_matches_ssh_failure_burst()
    {
        var rule = new R126_ExternalSshBruteCandidateRule();
        var baseTime = new DateTime(2026, 4, 30, 10, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 8; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateTcpRecord(
                source: "203.0.113.50",
                destination: "10.0.0.40",
                destinationPort: 22,
                protocol: "TCP",
                service: "SSH",
                info: $"failed password username=admin{index}",
                process: "sshd.exe"), baseTime.AddSeconds(index * 10)));
        }

        var evt = AssertSingleEvent(last!, "R126", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "matched_conditions", "count", "ssh.distinctUsers");
    }

    [Fact]
    public async Task R126_ignores_successful_ssh()
    {
        var rule = new R126_ExternalSshBruteCandidateRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateTcpRecord(
            source: "203.0.113.51",
            destination: "10.0.0.41",
            destinationPort: 22,
            protocol: "TCP",
            service: "SSH",
            info: "accepted publickey for root",
            process: "sshd.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R127_matches_external_admin_portal()
    {
        var rule = new R127_AdminPortalAccessFromInternetRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.1.0.5",
            destination: "198.51.100.40",
            destinationPort: 443,
            host: "admin.example.net",
            method: "GET",
            uri: "/wp-admin/index.php",
            headers: "Host: admin.example.net",
            info: "admin portal",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R127", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R127_ignores_generic_login_page()
    {
        var rule = new R127_AdminPortalAccessFromInternetRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.1.0.6",
            destination: "198.51.100.41",
            destinationPort: 443,
            host: "app.example.net",
            method: "GET",
            uri: "/login",
            headers: "Host: app.example.net",
            info: "user signin",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R128_matches_appliance_management_portal()
    {
        var rule = new R128_NetworkApplianceManagementExposureRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.1.0.7",
            destination: "198.51.100.50",
            destinationPort: 443,
            host: "fortigate-fw.example.net",
            method: "GET",
            uri: "/remote/login",
            headers: "Host: fortigate-fw.example.net",
            info: "fortigate sslvpn admin portal",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R128", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R128_ignores_vendor_documentation_site()
    {
        var rule = new R128_NetworkApplianceManagementExposureRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.1.0.8",
            destination: "198.51.100.51",
            destinationPort: 443,
            host: "docs.fortinet.com",
            method: "GET",
            uri: "/product-guides/fortigate",
            headers: "Host: docs.fortinet.com",
            info: "fortigate documentation",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R129_matches_suspicious_oidc_callback()
    {
        var rule = new R129_SuspiciousSamlOidcCallbackTrafficRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.0.10",
            destination: "198.51.100.60",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: "/signin-oidc?id_token=eyJhbGciOiJIUzI1NiJ9.payload.sig&state=abc",
            headers: "Host: app.example.com",
            info: "oidc callback",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R129", SeverityLevel.Medium, 0.55);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R129_ignores_ordinary_oidc_code_callback()
    {
        var rule = new R129_SuspiciousSamlOidcCallbackTrafficRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.2.0.11",
            destination: "198.51.100.61",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: "/signin-oidc?code=abc123&state=xyz",
            headers: "Host: app.example.com",
            info: "oidc callback",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R130_matches_credential_stuffing_burst()
    {
        var rule = new R130_CredentialStuffingAgainstWebLoginRule();
        var baseTime = new DateTime(2026, 4, 30, 10, 15, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 20; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "203.0.113.70",
                destination: "10.2.0.20",
                destinationPort: 443,
                host: "portal.internal.local",
                method: "POST",
                uri: "/login",
                headers: "Host: portal.internal.local",
                info: $"username=user{index}@example.com password=guess invalid password",
                service: "HTTPS",
                protocol: "HTTPS"), baseTime.AddSeconds(index * 8)));
        }

        var evt = AssertSingleEvent(last!, "R130", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "matched_conditions", "count", "web.distinctIdentities");
    }

    [Fact]
    public async Task R130_ignores_low_volume_login_failures()
    {
        var rule = new R130_CredentialStuffingAgainstWebLoginRule();
        var baseTime = new DateTime(2026, 4, 30, 10, 20, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 10; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "203.0.113.71",
                destination: "10.2.0.21",
                destinationPort: 443,
                host: "portal.internal.local",
                method: "POST",
                uri: "/login",
                headers: "Host: portal.internal.local",
                info: $"username=user{index}@example.com password=guess invalid password",
                service: "HTTPS",
                protocol: "HTTPS"), baseTime.AddSeconds(index * 10)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R131_matches_http_auth_failure_spike()
    {
        var rule = new R131_HttpAuthenticationFailureSpikeRule();
        var baseTime = new DateTime(2026, 4, 30, 10, 25, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 15; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.2.0.30",
                destination: "198.51.100.80",
                destinationPort: 443,
                host: "api.example.com",
                method: "GET",
                uri: "/api/auth/token?status=401",
                headers: "Authorization: Bearer abcdefghijklmnop\r\nWWW-Authenticate: Bearer",
                info: "401 unauthorized authentication failed",
                service: "HTTPS",
                protocol: "HTTPS"), baseTime.AddSeconds(index * 6)));
        }

        var evt = AssertSingleEvent(last!, "R131", SeverityLevel.Medium, 0.50);
        AssertEvidence(evt, "matched_conditions", "count");
    }

    [Fact]
    public async Task R131_ignores_generic_forbidden_spike_without_auth_context()
    {
        var rule = new R131_HttpAuthenticationFailureSpikeRule();
        var baseTime = new DateTime(2026, 4, 30, 10, 30, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 15; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.2.0.31",
                destination: "198.51.100.81",
                destinationPort: 443,
                host: "cdn.example.com",
                method: "GET",
                uri: "/static/app.js?status=403",
                headers: "Host: cdn.example.com",
                info: "403 forbidden",
                service: "HTTPS",
                protocol: "HTTPS"), baseTime.AddSeconds(index * 6)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R132_matches_rapid_country_change_for_identity()
    {
        var rule = new R132_RapidCountryChangeForSourceIdentityRule();
        var baseTime = new DateTime(2026, 4, 30, 10, 35, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        foreach (var (country, offset) in new[] { ("US", 0), ("DE", 60), ("SE", 120) })
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.2.0.40",
                destination: "198.51.100.90",
                destinationPort: 443,
                host: "login.example.com",
                method: "POST",
                uri: "/signin",
                headers: "Host: login.example.com",
                info: "username=alice@example.com login successful",
                service: "HTTPS",
                protocol: "HTTPS",
                srcCountryIso2: country), baseTime.AddSeconds(offset)));
        }

        var evt = AssertSingleEvent(last!, "R132", SeverityLevel.Medium, 0.45);
        AssertEvidence(evt, "matched_conditions", "identity.subject", "geo.country");
    }

    [Fact]
    public async Task R132_ignores_single_country_reuse()
    {
        var rule = new R132_RapidCountryChangeForSourceIdentityRule();
        var baseTime = new DateTime(2026, 4, 30, 11, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 3; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.2.0.41",
                destination: "198.51.100.91",
                destinationPort: 443,
                host: "login.example.com",
                method: "POST",
                uri: "/signin",
                headers: "Host: login.example.com",
                info: "username=charlie@example.com login successful",
                service: "HTTPS",
                protocol: "HTTPS",
                srcCountryIso2: "US"), baseTime.AddSeconds(index * 30)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R132_ignores_whois_country_without_source_geo()
    {
        var rule = new R132_RapidCountryChangeForSourceIdentityRule();
        var baseTime = new DateTime(2026, 4, 30, 11, 5, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        foreach (var (whoisCountry, offset) in new[] { ("US", 0), ("DE", 60), ("SE", 120) })
        {
            var record = CreateWebRecord(
                source: "10.2.0.42",
                destination: "198.51.100.92",
                destinationPort: 443,
                host: "login.example.com",
                method: "POST",
                uri: "/signin",
                headers: "Host: login.example.com",
                info: "username=dana@example.com login successful",
                service: "HTTPS",
                protocol: "HTTPS");
            record.WhoisCountry = whoisCountry;
            last = await rule.EvaluateAsync(CreateContext(record, baseTime.AddSeconds(offset)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R133_matches_basic_auth_over_cleartext()
    {
        var rule = new R133_BasicAuthenticationOverCleartextRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.10",
            destination: "198.51.100.100",
            destinationPort: 80,
            host: "app.example.com",
            method: "GET",
            uri: "/api",
            headers: "Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l",
            info: "GET /api HTTP/1.1",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R133", SeverityLevel.High, 0.75);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R133_ignores_basic_auth_over_https()
    {
        var rule = new R133_BasicAuthenticationOverCleartextRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.11",
            destination: "198.51.100.101",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: "/api",
            headers: "Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l",
            info: "GET /api HTTP/2",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R133_ignores_basic_auth_log_text_without_real_header()
    {
        var rule = new R133_BasicAuthenticationOverCleartextRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.12",
            destination: "198.51.100.102",
            destinationPort: 80,
            host: "app.example.com",
            method: "GET",
            uri: "/api",
            headers: "Host: app.example.com",
            info: "proxy log mentioned authorization: basic QWxhZGRpbjpPcGVuU2VzYW1l in prose",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R134_matches_sensitive_api_token_query()
    {
        var rule = new R134_ApiTokenInUrlQueryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.20",
            destination: "198.51.100.110",
            destinationPort: 443,
            host: "api.example.com",
            method: "GET",
            uri: "/v1/data?access_token=eyJhbGciOiJIUzI1NiJ9.payload.sig",
            headers: "Host: api.example.com",
            info: "api request",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R134", SeverityLevel.High, 0.65);
        AssertEvidence(evt, "matched_conditions", "token.parameter");
    }

    [Fact]
    public async Task R134_ignores_csrf_query_parameter()
    {
        var rule = new R134_ApiTokenInUrlQueryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.21",
            destination: "198.51.100.111",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: "/form?csrf_token=abcdef1234567890&state=abc",
            headers: "Host: app.example.com",
            info: "form submit",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R135_matches_bearer_token_over_cleartext()
    {
        var rule = new R135_BearerTokenOverCleartextHttpRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.30",
            destination: "198.51.100.120",
            destinationPort: 80,
            host: "api.example.com",
            method: "GET",
            uri: "/v1/profile",
            headers: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            info: "api request",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R135", SeverityLevel.High, 0.80);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R135_ignores_bearer_token_over_https()
    {
        var rule = new R135_BearerTokenOverCleartextHttpRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.31",
            destination: "198.51.100.121",
            destinationPort: 443,
            host: "api.example.com",
            method: "GET",
            uri: "/v1/profile",
            headers: "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            info: "api request",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R135_ignores_bearer_token_log_text_without_real_header()
    {
        var rule = new R135_BearerTokenOverCleartextHttpRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.32",
            destination: "198.51.100.122",
            destinationPort: 80,
            host: "api.example.com",
            method: "GET",
            uri: "/v1/profile",
            headers: "Host: api.example.com",
            info: "debug log referenced authorization: bearer eyJhbGciOiJIUzI1NiJ9.payload.sig in a sentence",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R136_matches_session_cookie_over_cleartext()
    {
        var rule = new R136_SessionCookieOverCleartextHttpRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.40",
            destination: "198.51.100.130",
            destinationPort: 80,
            host: "portal.example.com",
            method: "GET",
            uri: "/dashboard",
            headers: "Cookie: JSESSIONID=abc123def456ghi789",
            info: "page request",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R136", SeverityLevel.Medium, 0.55);
        AssertEvidence(evt, "matched_conditions", "session.cookieName");
    }

    [Fact]
    public async Task R136_ignores_analytics_cookie()
    {
        var rule = new R136_SessionCookieOverCleartextHttpRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.41",
            destination: "198.51.100.131",
            destinationPort: 80,
            host: "portal.example.com",
            method: "GET",
            uri: "/dashboard",
            headers: "Cookie: analytics_id=abc123def456ghi789",
            info: "page request",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R136_ignores_session_cookie_log_text_without_cookie_header()
    {
        var rule = new R136_SessionCookieOverCleartextHttpRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.3.0.42",
            destination: "198.51.100.132",
            destinationPort: 80,
            host: "portal.example.com",
            method: "GET",
            uri: "/dashboard",
            headers: "Host: portal.example.com",
            info: "trace note mentioned cookie: JSESSIONID=abc123def456ghi789 in application text",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R137_matches_reset_or_enrollment_burst()
    {
        var rule = new R137_PasswordResetOrEnrollmentSpikeRule();
        var baseTime = new DateTime(2026, 4, 30, 10, 45, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 8; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.4.0.10",
                destination: "198.51.100.140",
                destinationPort: 443,
                host: "login.example.com",
                method: "POST",
                uri: "/password-reset",
                headers: "Host: login.example.com",
                info: "reset password submit username=user@example.com",
                service: "HTTPS",
                protocol: "HTTPS"), baseTime.AddSeconds(index * 12)));
        }

        var evt = AssertSingleEvent(last!, "R137", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "count");
    }

    [Fact]
    public async Task R137_ignores_isolated_reset_page_view()
    {
        var rule = new R137_PasswordResetOrEnrollmentSpikeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.4.0.11",
            destination: "198.51.100.141",
            destinationPort: 443,
            host: "login.example.com",
            method: "GET",
            uri: "/password-reset",
            headers: "Host: login.example.com",
            info: "reset password page view",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public void Migrated_identity_access_rules_register_rule_owned_precision_profiles()
    {
        _ = new R123_SuspiciousVpnLoginPathRule();
        _ = new R130_CredentialStuffingAgainstWebLoginRule();
        _ = new R134_ApiTokenInUrlQueryRule();
        _ = new R137_PasswordResetOrEnrollmentSpikeRule();

        var r123 = RulePrecisionCatalog.GetProfile("R123", "IdentityAccess", SeverityLevel.High);
        var r130 = RulePrecisionCatalog.GetProfile("R130", "IdentityAccess", SeverityLevel.High);
        var r134 = RulePrecisionCatalog.GetProfile("R134", "IdentityAccess", SeverityLevel.High);
        var r137 = RulePrecisionCatalog.GetProfile("R137", "IdentityAccess", SeverityLevel.Medium);

        Assert.Contains(RuleTelemetryKind.Identity, r123.RequiredTelemetry);
        Assert.Equal(20, r130.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, r134.DefaultMode);
        Assert.Equal(TimeSpan.FromMinutes(5), r137.Window);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 30, 9, 0, 0, DateTimeKind.Utc));

    private static TrafficRecord CreateWebRecord(
        string source,
        string destination,
        int destinationPort,
        string host,
        string method,
        string uri,
        string headers,
        string info,
        string service,
        string protocol,
        string? process = null,
        string? srcCountryIso2 = null)
        => new()
        {
            // Synthetic HTTP/flow records must carry a real packet identity and
            // port roles; otherwise the provenance gate rejects them before
            // the intended rule behavior is evaluated.
            Id = Guid.NewGuid(),
            Source = source,
            SourcePort = 51000,
            Destination = destination,
            DestinationPort = destinationPort,
            IpVersion = 4,
            Protocol = protocol,
            ApplicationProtocol = protocol,
            ApplicationService = service,
            HttpHost = host,
            HttpMethod = method,
            HttpUri = uri,
            HttpRequestHeaders = headers,
            Info = info,
            ProcessName = process,
            SrcCountryIso2 = srcCountryIso2,
            IsTcp = true,
            Length = 2048,
            L4Len = 2048
        };

    private static TrafficRecord CreateTcpRecord(
        string source,
        string destination,
        int destinationPort,
        string protocol,
        string service,
        string info,
        string? process = null)
        => new()
        {
            // Synthetic HTTP/flow records must carry a real packet identity and
            // port roles; otherwise the provenance gate rejects them before
            // the intended rule behavior is evaluated.
            Id = Guid.NewGuid(),
            Source = source,
            SourcePort = 51000,
            Destination = destination,
            DestinationPort = destinationPort,
            IpVersion = 4,
            Protocol = protocol,
            ApplicationProtocol = protocol,
            ApplicationService = service,
            Info = info,
            ProcessName = process,
            IsTcp = true,
            Length = 1024,
            L4Len = 1024
        };

    private static DetectionEvent AssertSingleEvent(RuleEvaluationResult result, string ruleId, SeverityLevel minimumSeverity, double minimumConfidence)
    {
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal(ruleId, evt.RuleId);
        Assert.True(evt.ConfidenceScore >= minimumConfidence, $"Expected confidence >= {minimumConfidence:F2} but got {evt.ConfidenceScore:F2}.");
        Assert.True(evt.Severity >= minimumSeverity);
        Assert.NotNull(evt.StructuredEvidence);
        return evt;
    }

    private static void AssertEvidence(DetectionEvent evt, params string[] expectedKeys)
    {
        var keys = evt.StructuredEvidence!.Items.Select(item => item.Key).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var expected in expectedKeys)
            Assert.Contains(expected, keys);
    }
}
