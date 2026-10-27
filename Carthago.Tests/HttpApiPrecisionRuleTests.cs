using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class HttpApiPrecisionRuleTests
{
    private const string JwtNoneToken = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.xx";
    private const string JwtHs256Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.sig";

    public static IEnumerable<object[]> PrecisionHttpApiRules()
    {
        yield return new object[] { new R153_GraphqlIntrospectionQueryRule() };
        yield return new object[] { new R154_GraphqlBatchingAbuseRule() };
        yield return new object[] { new R155_RestApiEnumerationBurstRule() };
        yield return new object[] { new R156_JwtNoneAlgorithmIndicatorRule() };
        yield return new object[] { new R157_JwtInUrlQueryRule() };
        yield return new object[] { new R158_SwaggerOpenapiExposureProbeRule() };
        yield return new object[] { new R159_SpringActuatorExposureProbeRule() };
        yield return new object[] { new R160_KubernetesApiProbeRule() };
        yield return new object[] { new R161_DockerApiTcpExposureProbeRule() };
        yield return new object[] { new R162_RedisMemcachedWebProbeRule() };
        yield return new object[] { new R163_SsrfMetadataServiceProbeRule() };
        yield return new object[] { new R164_OpenRedirectParameterAbuseRule() };
        yield return new object[] { new R165_PhpinfoExposureProbeRule() };
        yield return new object[] { new R166_EnvironmentFileSecretProbeRule() };
        yield return new object[] { new R167_GitDirectoryExposureProbeRule() };
        yield return new object[] { new R168_BackupArchiveDownloadProbeRule() };
        yield return new object[] { new R169_AdminLoginBruteIndicatorRule() };
        yield return new object[] { new R170_XxePayloadIndicatorRule() };
        yield return new object[] { new R171_SoapActionExploitPatternRule() };
        yield return new object[] { new R172_ScannerUserAgentWithBrowserClaimMismatchRule() };
        yield return new object[] { new R173_SuspiciousCorsPreflightToAdminApiRule() };
        yield return new object[] { new R174_WebdavMethodAbuseRule() };
        yield return new object[] { new R175_HttpRequestSmugglingIndicatorRule() };
        yield return new object[] { new R176_HostHeaderInjectionIndicatorRule() };
        yield return new object[] { new R177_HighRiskFileUploadExtensionRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionHttpApiRules))]
    public async Task Precision_http_api_rules_return_no_match_without_http_context(IDetectionRule rule)
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
    [MemberData(nameof(PrecisionHttpApiRules))]
    public async Task Precision_http_api_rules_ignore_anytext_only_inputs(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.10.0.11",
            Destination = "203.0.113.11",
            DestinationPort = 9000,
            Protocol = "TCP",
            IsTcp = true,
            Info = "graphql __schema alg:none swagger actuator kubernetes docker metadata redirect phpinfo .env .git backup xxe soapaction sqlmap options webdav chunked x-forwarded-host shell.jsp",
            Length = 1024
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R153_matches_cross_boundary_graphql_introspection()
    {
        var rule = new R153_GraphqlIntrospectionQueryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.10",
            destination: "10.0.0.20",
            destinationPort: 443,
            host: "api.internal.local",
            method: "GET",
            uri: "/graphql?query=query{__schema{types{name}}}",
            headers: "Host: api.internal.local",
            info: "graphql introspection",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R153", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R153_ignores_ordinary_graphql_query()
    {
        var rule = new R153_GraphqlIntrospectionQueryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.11",
            destination: "10.0.0.21",
            destinationPort: 443,
            host: "api.internal.local",
            method: "GET",
            uri: "/graphql?query=query{viewer{id}}",
            headers: "Host: api.internal.local",
            info: "graphql query",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R154_matches_repeated_graphql_batching()
    {
        var rule = new R154_GraphqlBatchingAbuseRule();
        var baseTime = new DateTime(2026, 4, 30, 13, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 5; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "203.0.113.20",
                destination: "10.0.0.30",
                destinationPort: 443,
                host: "api.internal.local",
                method: "POST",
                uri: "/graphql",
                headers: "Host: api.internal.local",
                info: $"graphql batch [{{\"operationName\":\"User{index}\"}}]",
                service: "HTTPS",
                protocol: "HTTPS"), baseTime.AddSeconds(index * 15)));
        }

        var evt = AssertSingleEvent(last!, "R154", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "count");
    }

    [Fact]
    public async Task R154_ignores_single_graphql_request()
    {
        var rule = new R154_GraphqlBatchingAbuseRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.21",
            destination: "10.0.0.31",
            destinationPort: 443,
            host: "api.internal.local",
            method: "POST",
            uri: "/graphql",
            headers: "Host: api.internal.local",
            info: "graphql operationName Viewer",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R155_matches_distinct_api_enumeration_burst()
    {
        var rule = new R155_RestApiEnumerationBurstRule();
        var baseTime = new DateTime(2026, 4, 30, 13, 10, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 1; index <= 6; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "203.0.113.30",
                destination: "10.0.0.40",
                destinationPort: 443,
                host: "portal.internal.local",
                method: "GET",
                uri: $"/api/v1/users/{index}",
                headers: "Host: portal.internal.local",
                info: "api resource fetch",
                service: "HTTPS",
                protocol: "HTTPS",
                userAgent: "curl/8.7"), baseTime.AddSeconds(index * 10)));
        }

        var evt = AssertSingleEvent(last!, "R155", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "count");
    }

    [Fact]
    public async Task R155_ignores_outbound_browser_api_browsing()
    {
        var rule = new R155_RestApiEnumerationBurstRule();
        var baseTime = new DateTime(2026, 4, 30, 13, 15, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 1; index <= 6; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.0.0.50",
                destination: "198.51.100.50",
                destinationPort: 443,
                host: "api.example.com",
                method: "GET",
                uri: $"/api/v1/users/{index}",
                headers: "Host: api.example.com",
                info: "api resource fetch",
                service: "HTTPS",
                protocol: "HTTPS",
                userAgent: "Mozilla/5.0 Chrome/124.0"), baseTime.AddSeconds(index * 10)));
        }

        Assert.NotNull(last);
        Assert.False(last!.Matched);
    }

    [Fact]
    public async Task R156_matches_decoded_jwt_none_algorithm()
    {
        var rule = new R156_JwtNoneAlgorithmIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.60",
            destination: "198.51.100.60",
            destinationPort: 443,
            host: "auth.example.com",
            method: "GET",
            uri: "/api/session",
            headers: $"Authorization: Bearer {JwtNoneToken}",
            info: "authorization bearer",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R156", SeverityLevel.High, 0.60);
        AssertEvidence(evt, "matched_conditions", "jwt.source");
    }

    [Fact]
    public async Task R156_ignores_signed_jwt()
    {
        var rule = new R156_JwtNoneAlgorithmIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.61",
            destination: "198.51.100.61",
            destinationPort: 443,
            host: "auth.example.com",
            method: "GET",
            uri: "/api/session",
            headers: $"Authorization: Bearer {JwtHs256Token}",
            info: "authorization bearer",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R157_matches_jwt_in_query_parameter()
    {
        var rule = new R157_JwtInUrlQueryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.70",
            destination: "198.51.100.70",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: $"/callback?id_token={JwtHs256Token}&state=abc",
            headers: "Host: app.example.com",
            info: "oidc callback",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R157", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "query.parameter");
    }

    [Fact]
    public async Task R157_ignores_opaque_query_token()
    {
        var rule = new R157_JwtInUrlQueryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.71",
            destination: "198.51.100.71",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: "/callback?access_token=opaque1234567890&state=abc",
            headers: "Host: app.example.com",
            info: "callback",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R158_matches_swagger_discovery_path()
    {
        var rule = new R158_SwaggerOpenapiExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.80",
            destination: "10.0.0.80",
            destinationPort: 443,
            host: "api.internal.local",
            method: "GET",
            uri: "/v3/api-docs",
            headers: "Host: api.internal.local",
            info: "swagger probe",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R158", SeverityLevel.Medium, 0.30);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R158_ignores_public_swagger_documentation_host()
    {
        var rule = new R158_SwaggerOpenapiExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.81",
            destination: "198.51.100.81",
            destinationPort: 443,
            host: "petstore.swagger.io",
            method: "GET",
            uri: "/swagger-ui.html",
            headers: "Host: petstore.swagger.io",
            info: "public docs",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R159_matches_sensitive_actuator_path()
    {
        var rule = new R159_SpringActuatorExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.90",
            destination: "10.0.0.90",
            destinationPort: 443,
            host: "spring.internal.local",
            method: "GET",
            uri: "/actuator/env",
            headers: "Host: spring.internal.local",
            info: "actuator probe",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R159", SeverityLevel.High, 0.40);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R159_ignores_actuator_health()
    {
        var rule = new R159_SpringActuatorExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.91",
            destination: "10.0.0.91",
            destinationPort: 443,
            host: "spring.internal.local",
            method: "GET",
            uri: "/actuator/health",
            headers: "Host: spring.internal.local",
            info: "health check",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R160_matches_kubernetes_api_path()
    {
        var rule = new R160_KubernetesApiProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.100",
            destination: "10.0.0.100",
            destinationPort: 6443,
            host: "kubernetes.internal.local",
            method: "GET",
            uri: "/api/v1/namespaces/default/pods",
            headers: "Host: kubernetes.internal.local",
            info: "kubernetes api",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R160", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "matched_conditions", "http.path", "network.destinationPort");
    }

    [Fact]
    public async Task R160_ignores_generic_application_api_path()
    {
        var rule = new R160_KubernetesApiProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.101",
            destination: "10.0.0.101",
            destinationPort: 443,
            host: "app.internal.local",
            method: "GET",
            uri: "/api/v1/products",
            headers: "Host: app.internal.local",
            info: "rest api",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R161_matches_docker_api_path()
    {
        var rule = new R161_DockerApiTcpExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.110",
            destination: "10.0.0.110",
            destinationPort: 2375,
            host: "docker.internal.local",
            method: "GET",
            uri: "/containers/json",
            headers: "Host: docker.internal.local",
            info: "docker api",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R161", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "matched_conditions", "http.path", "network.destinationPort");
    }

    [Fact]
    public async Task R161_ignores_ordinary_version_endpoint()
    {
        var rule = new R161_DockerApiTcpExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.111",
            destination: "10.0.0.111",
            destinationPort: 443,
            host: "app.internal.local",
            method: "GET",
            uri: "/version",
            headers: "Host: app.internal.local",
            info: "application version",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R162_matches_cache_admin_probe()
    {
        var rule = new R162_RedisMemcachedWebProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.120",
            destination: "10.0.0.120",
            destinationPort: 6379,
            host: "cache.internal.local",
            method: "GET",
            uri: "/stats",
            headers: "Host: cache.internal.local",
            info: "redis stats",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R162", SeverityLevel.Medium, 0.30);
        AssertEvidence(evt, "matched_conditions", "http.path", "network.destinationPort");
    }

    [Fact]
    public async Task R162_ignores_generic_stats_endpoint()
    {
        var rule = new R162_RedisMemcachedWebProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.121",
            destination: "10.0.0.121",
            destinationPort: 8080,
            host: "app.internal.local",
            method: "GET",
            uri: "/stats",
            headers: "Host: app.internal.local",
            info: "application stats",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R163_matches_metadata_credential_probe_from_non_agent()
    {
        var rule = new R163_SsrfMetadataServiceProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.130",
            destination: "169.254.169.254",
            destinationPort: 80,
            host: "169.254.169.254",
            method: "GET",
            uri: "/latest/meta-data/iam/security-credentials/",
            headers: "Host: 169.254.169.254",
            info: "metadata request",
            service: "HTTP",
            protocol: "HTTP",
            process: "python.exe")));

        var evt = AssertSingleEvent(result, "R163", SeverityLevel.Critical, 0.60);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R163_ignores_known_metadata_agent_process()
    {
        var rule = new R163_SsrfMetadataServiceProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.131",
            destination: "169.254.169.254",
            destinationPort: 80,
            host: "169.254.169.254",
            method: "GET",
            uri: "/latest/meta-data/iam/security-credentials/",
            headers: "Host: 169.254.169.254",
            info: "metadata request",
            service: "HTTP",
            protocol: "HTTP",
            process: "amazon-ssm-agent.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R164_matches_suspicious_redirect_target()
    {
        var rule = new R164_OpenRedirectParameterAbuseRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.140",
            destination: "198.51.100.140",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: "/redirect?next=https://evil.example/phish",
            headers: "Host: app.example.com",
            info: "redirect request",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R164", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "query.parameter", "redirect.target");
    }

    [Fact]
    public async Task R164_ignores_same_site_oidc_redirect()
    {
        var rule = new R164_OpenRedirectParameterAbuseRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.0.0.141",
            destination: "198.51.100.141",
            destinationPort: 443,
            host: "login.example.com",
            method: "GET",
            uri: "https://login.example.com/oauth2/start?redirect_uri=https://app.example.com/callback",
            headers: "Host: login.example.com",
            info: "oidc redirect",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R165_matches_phpinfo_path()
    {
        var rule = new R165_PhpinfoExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.150",
            destination: "10.0.0.150",
            destinationPort: 80,
            host: "web.internal.local",
            method: "GET",
            uri: "/phpinfo.php",
            headers: "Host: web.internal.local",
            info: "phpinfo probe",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R165", SeverityLevel.Low, 0.20);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R165_ignores_generic_info_page()
    {
        var rule = new R165_PhpinfoExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.151",
            destination: "10.0.0.151",
            destinationPort: 80,
            host: "web.internal.local",
            method: "GET",
            uri: "/info",
            headers: "Host: web.internal.local",
            info: "info page",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R166_matches_secret_environment_file_path()
    {
        var rule = new R166_EnvironmentFileSecretProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.160",
            destination: "10.0.0.160",
            destinationPort: 80,
            host: "web.internal.local",
            method: "GET",
            uri: "/.env",
            headers: "Host: web.internal.local",
            info: "env probe",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R166", SeverityLevel.High, 0.40);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R166_ignores_ordinary_well_known_path()
    {
        var rule = new R166_EnvironmentFileSecretProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.161",
            destination: "10.0.0.161",
            destinationPort: 80,
            host: "web.internal.local",
            method: "GET",
            uri: "/.well-known/security.txt",
            headers: "Host: web.internal.local",
            info: "security txt",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R167_matches_exposed_git_path()
    {
        var rule = new R167_GitDirectoryExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.170",
            destination: "10.0.0.170",
            destinationPort: 80,
            host: "web.internal.local",
            method: "GET",
            uri: "/.git/config",
            headers: "Host: web.internal.local",
            info: "git probe",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R167", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R167_ignores_git_help_page()
    {
        var rule = new R167_GitDirectoryExposureProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.171",
            destination: "10.0.0.171",
            destinationPort: 80,
            host: "web.internal.local",
            method: "GET",
            uri: "/git/help",
            headers: "Host: web.internal.local",
            info: "git help",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R168_matches_backup_archive_filename()
    {
        var rule = new R168_BackupArchiveDownloadProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.180",
            destination: "10.0.0.180",
            destinationPort: 80,
            host: "web.internal.local",
            method: "GET",
            uri: "/db_backup_2026.sql.gz",
            headers: "Host: web.internal.local",
            info: "backup archive",
            service: "HTTP",
            protocol: "HTTP")));

        var evt = AssertSingleEvent(result, "R168", SeverityLevel.Medium, 0.30);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R168_ignores_ordinary_report_archive()
    {
        var rule = new R168_BackupArchiveDownloadProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.181",
            destination: "10.0.0.181",
            destinationPort: 80,
            host: "web.internal.local",
            method: "GET",
            uri: "/downloads/report.zip",
            headers: "Host: web.internal.local",
            info: "report archive",
            service: "HTTP",
            protocol: "HTTP")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R169_matches_repeated_admin_login_failures()
    {
        var rule = new R169_AdminLoginBruteIndicatorRule();
        var baseTime = new DateTime(2026, 4, 30, 13, 30, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 6; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "203.0.113.190",
                destination: "10.0.0.190",
                destinationPort: 443,
                host: "admin.internal.local",
                method: "POST",
                uri: "/admin/login",
                headers: "Host: admin.internal.local",
                info: $"username=admin invalid password {index}",
                service: "HTTPS",
                protocol: "HTTPS"), baseTime.AddSeconds(index * 20)));
        }

        var evt = AssertSingleEvent(last!, "R169", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "count");
    }

    [Fact]
    public async Task R169_ignores_successful_admin_login()
    {
        var rule = new R169_AdminLoginBruteIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.191",
            destination: "10.0.0.191",
            destinationPort: 443,
            host: "admin.internal.local",
            method: "POST",
            uri: "/admin/login",
            headers: "Host: admin.internal.local",
            info: "username=admin login successful",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R170_matches_xml_xxe_payload()
    {
        var rule = new R170_XxePayloadIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.200",
            destination: "10.0.0.200",
            destinationPort: 443,
            host: "soap.internal.local",
            method: "POST",
            uri: "/soap/order?xml=%3C!DOCTYPE%20foo%20%5B%3C!ENTITY%20xxe%20SYSTEM%20%22file:///etc/passwd%22%3E%5D%3E",
            headers: "Host: soap.internal.local\r\nContent-Type: text/xml",
            info: "xml request with query-encoded declaration",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R170", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R170_ignores_ordinary_xml_request()
    {
        var rule = new R170_XxePayloadIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.201",
            destination: "10.0.0.201",
            destinationPort: 443,
            host: "soap.internal.local",
            method: "POST",
            uri: "/soap/order",
            headers: "Host: soap.internal.local\r\nContent-Type: text/xml",
            info: "<Order><Id>1</Id></Order>",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R171_matches_suspicious_soapaction()
    {
        var rule = new R171_SoapActionExploitPatternRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.210",
            destination: "10.0.0.210",
            destinationPort: 443,
            host: "soap.internal.local",
            method: "POST",
            uri: "/service.asmx",
            headers: "Host: soap.internal.local\r\nContent-Type: text/xml\r\nSOAPAction: \"executeCommand\"",
            info: "soap action",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R171", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "soap.action");
    }

    [Fact]
    public async Task R171_ignores_ordinary_soapaction()
    {
        var rule = new R171_SoapActionExploitPatternRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.211",
            destination: "10.0.0.211",
            destinationPort: 443,
            host: "soap.internal.local",
            method: "POST",
            uri: "/service.asmx",
            headers: "Host: soap.internal.local\r\nContent-Type: text/xml\r\nSOAPAction: \"GetUser\"",
            info: "soap action",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R172_matches_scanner_user_agent_browser_mismatch()
    {
        var rule = new R172_ScannerUserAgentWithBrowserClaimMismatchRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.220",
            destination: "10.0.0.220",
            destinationPort: 443,
            host: "portal.internal.local",
            method: "GET",
            uri: "/admin",
            headers: "Host: portal.internal.local",
            info: "scan",
            service: "HTTPS",
            protocol: "HTTPS",
            userAgent: "sqlmap/1.8 Mozilla/5.0")));

        var evt = AssertSingleEvent(result, "R172", SeverityLevel.Low, 0.30);
        AssertEvidence(evt, "matched_conditions", "http.user_agent");
    }

    [Fact]
    public async Task R172_ignores_normal_browser_user_agent()
    {
        var rule = new R172_ScannerUserAgentWithBrowserClaimMismatchRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.221",
            destination: "10.0.0.221",
            destinationPort: 443,
            host: "portal.internal.local",
            method: "GET",
            uri: "/admin",
            headers: "Host: portal.internal.local",
            info: "browse",
            service: "HTTPS",
            protocol: "HTTPS",
            userAgent: "Mozilla/5.0 Chrome/124.0")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R173_matches_admin_api_cors_preflight()
    {
        var rule = new R173_SuspiciousCorsPreflightToAdminApiRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.230",
            destination: "10.0.0.230",
            destinationPort: 443,
            host: "portal.internal.local",
            method: "OPTIONS",
            uri: "/admin/api/users",
            headers: "Host: portal.internal.local\r\nAccess-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: authorization,x-api-key\r\nOrigin: https://evil.example",
            info: "cors preflight",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R173", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "matched_conditions", "http.path");
    }

    [Fact]
    public async Task R173_ignores_public_same_site_api_preflight()
    {
        var rule = new R173_SuspiciousCorsPreflightToAdminApiRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.231",
            destination: "10.0.0.231",
            destinationPort: 443,
            host: "app.example.com",
            method: "OPTIONS",
            uri: "/api/public/items",
            headers: "Host: app.example.com\r\nAccess-Control-Request-Method: GET\r\nOrigin: https://app.example.com",
            info: "cors preflight",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R174_matches_suspicious_webdav_method()
    {
        var rule = new R174_WebdavMethodAbuseRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.240",
            destination: "10.0.0.240",
            destinationPort: 443,
            host: "share.internal.local",
            method: "PROPFIND",
            uri: "/webdav/",
            headers: "Host: share.internal.local\r\nDepth: infinity",
            info: "webdav probe",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R174", SeverityLevel.Medium, 0.30);
        AssertEvidence(evt, "matched_conditions", "http.method", "http.path");
    }

    [Fact]
    public async Task R174_ignores_benign_caldav_discovery()
    {
        var rule = new R174_WebdavMethodAbuseRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.241",
            destination: "10.0.0.241",
            destinationPort: 443,
            host: "share.internal.local",
            method: "PROPFIND",
            uri: "/.well-known/caldav",
            headers: "Host: share.internal.local\r\nDepth: 1",
            info: "caldav",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R175_matches_conflicting_http_framing()
    {
        var rule = new R175_HttpRequestSmugglingIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.250",
            destination: "10.0.0.250",
            destinationPort: 443,
            host: "edge.internal.local",
            method: "POST",
            uri: "/submit",
            headers: "Host: edge.internal.local\r\nContent-Length: 10\r\nTransfer-Encoding: chunked",
            info: "smuggling test",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R175", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "matched_conditions", "smuggling.mode", "http.method");
    }

    [Fact]
    public async Task R175_ignores_standard_content_length_request()
    {
        var rule = new R175_HttpRequestSmugglingIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.251",
            destination: "10.0.0.251",
            destinationPort: 443,
            host: "edge.internal.local",
            method: "POST",
            uri: "/submit",
            headers: "Host: edge.internal.local\r\nContent-Length: 10",
            info: "normal post",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R176_matches_suspicious_forwarded_host()
    {
        var rule = new R176_HostHeaderInjectionIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.260",
            destination: "10.0.0.260",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: "/",
            headers: "Host: app.example.com\r\nX-Forwarded-Host: 127.0.0.1",
            info: "host header test",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R176", SeverityLevel.Medium, 0.20);
        AssertEvidence(evt, "matched_conditions", "host_header.detail");
    }

    [Fact]
    public async Task R176_ignores_ordinary_forwarded_host()
    {
        var rule = new R176_HostHeaderInjectionIndicatorRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.261",
            destination: "10.0.0.261",
            destinationPort: 443,
            host: "app.example.com",
            method: "GET",
            uri: "/",
            headers: "Host: app.example.com\r\nX-Forwarded-Host: app.example.com",
            info: "proxy request",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R177_matches_high_risk_upload_filename()
    {
        var rule = new R177_HighRiskFileUploadExtensionRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.270",
            destination: "10.0.0.270",
            destinationPort: 443,
            host: "upload.internal.local",
            method: "POST",
            uri: "/upload",
            headers: "Host: upload.internal.local\r\nContent-Type: multipart/form-data; boundary=abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.jsp\"",
            info: "file upload",
            service: "HTTPS",
            protocol: "HTTPS")));

        var evt = AssertSingleEvent(result, "R177", SeverityLevel.High, 0.50);
        AssertEvidence(evt, "matched_conditions", "upload.filename", "http.path");
    }

    [Fact]
    public async Task R177_ignores_benign_image_upload()
    {
        var rule = new R177_HighRiskFileUploadExtensionRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "203.0.113.271",
            destination: "10.0.0.271",
            destinationPort: 443,
            host: "upload.internal.local",
            method: "POST",
            uri: "/upload",
            headers: "Host: upload.internal.local\r\nContent-Type: multipart/form-data; boundary=abc\r\nContent-Disposition: form-data; name=\"file\"; filename=\"photo.png\"",
            info: "file upload",
            service: "HTTPS",
            protocol: "HTTPS")));

        Assert.False(result.Matched);
    }

    [Fact]
    public void Migrated_http_api_rules_register_rule_owned_precision_profiles()
    {
        _ = new R154_GraphqlBatchingAbuseRule();
        _ = new R156_JwtNoneAlgorithmIndicatorRule();
        _ = new R169_AdminLoginBruteIndicatorRule();
        _ = new R177_HighRiskFileUploadExtensionRule();

        var r154 = RulePrecisionCatalog.GetProfile("R154", "HttpApi", SeverityLevel.Medium);
        var r156 = RulePrecisionCatalog.GetProfile("R156", "HttpApi", SeverityLevel.High);
        var r169 = RulePrecisionCatalog.GetProfile("R169", "HttpApi", SeverityLevel.Medium);
        var r177 = RulePrecisionCatalog.GetProfile("R177", "HttpApi", SeverityLevel.High);

        Assert.Equal(5, r154.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, r156.DefaultMode);
        Assert.Equal(TimeSpan.FromMinutes(10), r169.Window);
        Assert.Equal(RuleRuntimeMode.Alert, r177.DefaultMode);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 30, 12, 0, 0, DateTimeKind.Utc));

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
        string? userAgent = null)
        => new()
        {
            Source = source,
            Destination = destination,
            DestinationPort = destinationPort,
            Protocol = protocol,
            ApplicationProtocol = protocol,
            ApplicationService = service,
            HttpHost = host,
            HttpMethod = method,
            HttpUri = uri,
            HttpRequestHeaders = headers,
            HttpUserAgent = userAgent,
            Info = info,
            ProcessName = process,
            IsTcp = true,
            Length = 2048,
            L4Len = 2048
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
