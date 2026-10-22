using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class CloudDevPrecisionRuleTests
{
    public static IEnumerable<object[]> PrecisionCloudDevRules()
    {
        yield return new object[] { new R198_AwsMetadataCredentialRetrievalRule() };
        yield return new object[] { new R199_GcpMetadataCredentialRetrievalRule() };
        yield return new object[] { new R200_AzureMetadataCredentialRetrievalRule() };
        yield return new object[] { new R201_KubernetesServiceAccountTokenAccessRule() };
        yield return new object[] { new R202_DockerRegistryPushPullAnomalyRule() };
        yield return new object[] { new R203_ContainerImageLayerBulkDownloadRule() };
        yield return new object[] { new R204_TerraformStateFileAccessRule() };
        yield return new object[] { new R205_CiCdSecretTokenInUrlRule() };
        yield return new object[] { new R206_GitCloneFromUnknownExternalHostRule() };
        yield return new object[] { new R207_GitPushToUnknownExternalHostRule() };
        yield return new object[] { new R208_PackageManagerToSuspiciousRegistryRule() };
        yield return new object[] { new R209_NpmInstallScriptBeaconPatternRule() };
        yield return new object[] { new R210_PypiPackageDownloadFromRareDomainRule() };
        yield return new object[] { new R211_PowershellGalleryExternalScriptPullRule() };
        yield return new object[] { new R212_CurlWgetRawScriptToShellRule() };
        yield return new object[] { new R213_CloudStoragePresignedUrlMassAccessRule() };
        yield return new object[] { new R214_S3BucketListingProbeRule() };
        yield return new object[] { new R215_AzureBlobContainerEnumerationRule() };
        yield return new object[] { new R216_GoogleStorageBucketEnumerationRule() };
        yield return new object[] { new R217_SlackWebhookExfiltrationRule() };
    }

    [Theory]
    [MemberData(nameof(PrecisionCloudDevRules))]
    public async Task Precision_clouddev_rules_return_no_match_without_http_context(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.40.0.10",
            Destination = "10.40.0.20",
            DestinationPort = 9000,
            Protocol = "TCP",
            IsTcp = true,
            Length = 512
        }));

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Theory]
    [MemberData(nameof(PrecisionCloudDevRules))]
    public async Task Precision_clouddev_rules_ignore_anytext_only_inputs(IDetectionRule rule)
    {
        var result = await rule.EvaluateAsync(CreateContext(new TrafficRecord
        {
            Source = "10.40.0.11",
            Destination = "198.51.100.11",
            DestinationPort = 443,
            Protocol = "TCP",
            IsTcp = true,
            Info = "metadata registry package git signed-url slack webhook postinstall tfstate token list",
            HttpHost = "docs.example.com",
            Length = 1024
        }));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R198_matches_aws_imds_credential_request()
    {
        var rule = new R198_AwsMetadataCredentialRetrievalRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.10",
            destination: "169.254.169.254",
            destinationPort: 80,
            host: "169.254.169.254",
            method: "GET",
            uri: "/latest/meta-data/iam/security-credentials/my-role",
            headers: "Host: 169.254.169.254\r\nX-aws-ec2-metadata-token: abcdefghijklmnop",
            info: "imds credential request",
            service: "HTTP",
            protocol: "HTTP",
            process: "python.exe")));

        var evt = AssertSingleEvent(result, "R198", SeverityLevel.Critical, 0.55);
        AssertEvidence(evt, "http.path", "matched_conditions");
    }

    [Fact]
    public async Task R198_ignores_expected_aws_metadata_agent()
    {
        var rule = new R198_AwsMetadataCredentialRetrievalRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.11",
            destination: "169.254.169.254",
            destinationPort: 80,
            host: "169.254.169.254",
            method: "GET",
            uri: "/latest/meta-data/iam/security-credentials/my-role",
            headers: "Host: 169.254.169.254\r\nX-aws-ec2-metadata-token: abcdefghijklmnop",
            info: "imds credential request",
            service: "HTTP",
            protocol: "HTTP",
            process: "amazon-ssm-agent.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R199_matches_gcp_metadata_token_request()
    {
        var rule = new R199_GcpMetadataCredentialRetrievalRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.20",
            destination: "169.254.169.254",
            destinationPort: 80,
            host: "metadata.google.internal",
            method: "GET",
            uri: "/computeMetadata/v1/instance/service-accounts/default/token",
            headers: "Host: metadata.google.internal\r\nMetadata-Flavor: Google",
            info: "gcp metadata token request",
            service: "HTTP",
            protocol: "HTTP",
            process: "python.exe")));

        var evt = AssertSingleEvent(result, "R199", SeverityLevel.Critical, 0.55);
        AssertEvidence(evt, "http.path", "matched_conditions");
    }

    [Fact]
    public async Task R199_ignores_google_guest_agent_metadata_request()
    {
        var rule = new R199_GcpMetadataCredentialRetrievalRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.21",
            destination: "169.254.169.254",
            destinationPort: 80,
            host: "metadata.google.internal",
            method: "GET",
            uri: "/computeMetadata/v1/instance/service-accounts/default/token",
            headers: "Host: metadata.google.internal\r\nMetadata-Flavor: Google",
            info: "gcp metadata token request",
            service: "HTTP",
            protocol: "HTTP",
            process: "google-guest-agent.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R200_matches_azure_imds_token_request()
    {
        var rule = new R200_AzureMetadataCredentialRetrievalRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.30",
            destination: "169.254.169.254",
            destinationPort: 80,
            host: "169.254.169.254",
            method: "GET",
            uri: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            headers: "Host: 169.254.169.254\r\nMetadata: true",
            info: "azure imds token request",
            service: "HTTP",
            protocol: "HTTP",
            process: "powershell.exe")));

        var evt = AssertSingleEvent(result, "R200", SeverityLevel.Critical, 0.55);
        AssertEvidence(evt, "http.path", "matched_conditions");
    }

    [Fact]
    public async Task R200_ignores_waagent_imds_request()
    {
        var rule = new R200_AzureMetadataCredentialRetrievalRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.31",
            destination: "169.254.169.254",
            destinationPort: 80,
            host: "169.254.169.254",
            method: "GET",
            uri: "/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            headers: "Host: 169.254.169.254\r\nMetadata: true",
            info: "azure imds token request",
            service: "HTTP",
            protocol: "HTTP",
            process: "waagent.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R201_matches_service_account_token_access()
    {
        var rule = new R201_KubernetesServiceAccountTokenAccessRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.40",
            destination: "10.40.1.41",
            destinationPort: 443,
            host: "kubernetes.default.svc",
            method: "GET",
            uri: "/var/run/secrets/kubernetes.io/serviceaccount/token",
            headers: "Host: kubernetes.default.svc",
            info: "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "bash.exe")));

        var evt = AssertSingleEvent(result, "R201", SeverityLevel.Critical, 0.40);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R201_ignores_kubelet_token_access()
    {
        var rule = new R201_KubernetesServiceAccountTokenAccessRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.42",
            destination: "10.40.1.43",
            destinationPort: 443,
            host: "kubernetes.default.svc",
            method: "GET",
            uri: "/var/run/secrets/kubernetes.io/serviceaccount/token",
            headers: "Host: kubernetes.default.svc",
            info: "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "kubelet.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R202_matches_repeated_custom_registry_activity()
    {
        var rule = new R202_DockerRegistryPushPullAnomalyRule();
        var baseTime = new DateTime(2026, 4, 30, 16, 0, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 6; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.40.1.50",
                destination: "198.51.100.50",
                destinationPort: 443,
                host: "registry.shadow.example",
                method: "POST",
                uri: $"/v2/team/app/blobs/uploads/session{index}",
                headers: "Host: registry.shadow.example\r\nDocker-Distribution-Api-Version: registry/2.0",
                info: "docker-registry upload",
                service: "HTTPS",
                protocol: "HTTPS",
                process: "docker.exe"), baseTime.AddSeconds(index * 15)));
        }

        var evt = AssertSingleEvent(last!, "R202", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "baseline.reason", "count", "matched_conditions");
    }

    [Fact]
    public async Task R202_ignores_official_public_registry()
    {
        var rule = new R202_DockerRegistryPushPullAnomalyRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.51",
            destination: "198.51.100.51",
            destinationPort: 443,
            host: "ghcr.io",
            method: "POST",
            uri: "/v2/team/app/blobs/uploads/session1",
            headers: "Host: ghcr.io\r\nDocker-Distribution-Api-Version: registry/2.0",
            info: "docker-registry upload",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "docker.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R203_matches_bulk_container_layer_download()
    {
        var rule = new R203_ContainerImageLayerBulkDownloadRule();
        var baseTime = new DateTime(2026, 4, 30, 16, 10, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 6; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.40.1.60",
                destination: "198.51.100.60",
                destinationPort: 443,
                host: "layers.shadow.example",
                method: "GET",
                uri: $"/v2/team/app/blobs/sha256:abcdefabcdefabcdefabcdefabcdefab{index}",
                headers: "Host: layers.shadow.example\r\nDocker-Distribution-Api-Version: registry/2.0",
                info: "docker-content-digest",
                service: "HTTPS",
                protocol: "HTTPS",
                process: "docker.exe",
                length: 400_000), baseTime.AddSeconds(index * 15)));
        }

        var evt = AssertSingleEvent(last!, "R203", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "baseline.reason", "count", "flow.bytes", "matched_conditions");
    }

    [Fact]
    public async Task R203_ignores_single_layer_download()
    {
        var rule = new R203_ContainerImageLayerBulkDownloadRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.61",
            destination: "198.51.100.61",
            destinationPort: 443,
            host: "layers.shadow.example",
            method: "GET",
            uri: "/v2/team/app/blobs/sha256:abcdefabcdefabcdefabcdefabcdefab1",
            headers: "Host: layers.shadow.example\r\nDocker-Distribution-Api-Version: registry/2.0",
            info: "docker-content-digest",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "docker.exe",
            length: 400_000)));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R204_matches_terraform_state_access()
    {
        var rule = new R204_TerraformStateFileAccessRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.70",
            destination: "198.51.100.70",
            destinationPort: 443,
            host: "state-transfer.example",
            method: "GET",
            uri: "/infra/terraform.tfstate",
            headers: "Host: state-transfer.example",
            info: "terraform state download",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "curl.exe")));

        var evt = AssertSingleEvent(result, "R204", SeverityLevel.High, 0.35);
        AssertEvidence(evt, "http.path", "matched_conditions");
    }

    [Fact]
    public async Task R204_ignores_terraform_documentation_path()
    {
        var rule = new R204_TerraformStateFileAccessRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.71",
            destination: "198.51.100.71",
            destinationPort: 443,
            host: "developer.example",
            method: "GET",
            uri: "/docs/terraform-state.html",
            headers: "Host: developer.example",
            info: "terraform docs",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "chrome.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R205_matches_cicd_secret_token_in_query_string()
    {
        var rule = new R205_CiCdSecretTokenInUrlRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.80",
            destination: "198.51.100.80",
            destinationPort: 443,
            host: "ci-shadow.example",
            method: "GET",
            uri: "/callback?github_token=ghp_abcdefghijklmnopqrstuvwxyz",
            headers: "Host: ci-shadow.example",
            info: "callback",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe")));

        var evt = AssertSingleEvent(result, "R205", SeverityLevel.High, 0.40);
        AssertEvidence(evt, "query.parameter", "matched_conditions");
    }

    [Fact]
    public async Task R205_ignores_short_placeholder_token_value()
    {
        var rule = new R205_CiCdSecretTokenInUrlRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.81",
            destination: "198.51.100.81",
            destinationPort: 443,
            host: "ci-shadow.example",
            method: "GET",
            uri: "/callback?github_token=short",
            headers: "Host: ci-shadow.example",
            info: "callback",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R206_matches_git_clone_from_unknown_external_host()
    {
        var rule = new R206_GitCloneFromUnknownExternalHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.90",
            destination: "198.51.100.90",
            destinationPort: 443,
            host: "git-shadow.example",
            method: "GET",
            uri: "/team/repo/info/refs?service=git-upload-pack",
            headers: "Host: git-shadow.example\r\nUser-Agent: git/2.43.0",
            info: "git clone",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "git.exe")));

        var evt = AssertSingleEvent(result, "R206", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "baseline.reason", "matched_conditions");
    }

    [Fact]
    public async Task R206_ignores_github_clone()
    {
        var rule = new R206_GitCloneFromUnknownExternalHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.91",
            destination: "140.82.112.3",
            destinationPort: 443,
            host: "github.com",
            method: "GET",
            uri: "/team/repo/info/refs?service=git-upload-pack",
            headers: "Host: github.com\r\nUser-Agent: git/2.43.0",
            info: "git clone",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "git.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R207_matches_git_push_to_unknown_external_host()
    {
        var rule = new R207_GitPushToUnknownExternalHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.100",
            destination: "198.51.100.100",
            destinationPort: 443,
            host: "git-push.example",
            method: "POST",
            uri: "/team/repo/git-receive-pack",
            headers: "Host: git-push.example\r\nUser-Agent: git/2.43.0",
            info: "git push",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "git.exe")));

        var evt = AssertSingleEvent(result, "R207", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "baseline.reason", "matched_conditions");
    }

    [Fact]
    public async Task R207_ignores_gitlab_push()
    {
        var rule = new R207_GitPushToUnknownExternalHostRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.101",
            destination: "198.51.100.101",
            destinationPort: 443,
            host: "gitlab.com",
            method: "POST",
            uri: "/team/repo/git-receive-pack",
            headers: "Host: gitlab.com\r\nUser-Agent: git/2.43.0",
            info: "git push",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "git.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R208_matches_package_manager_to_custom_registry()
    {
        var rule = new R208_PackageManagerToSuspiciousRegistryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.110",
            destination: "198.51.100.110",
            destinationPort: 443,
            host: "registry.shadow.example",
            method: "GET",
            uri: "/-/package/private-lib/dist-tags",
            headers: "Host: registry.shadow.example\r\nUser-Agent: npm/10.0.0",
            info: "npm registry request",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "npm.exe")));

        var evt = AssertSingleEvent(result, "R208", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "baseline.reason", "matched_conditions");
    }

    [Fact]
    public async Task R208_ignores_official_npm_registry()
    {
        var rule = new R208_PackageManagerToSuspiciousRegistryRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.111",
            destination: "104.16.30.34",
            destinationPort: 443,
            host: "registry.npmjs.org",
            method: "GET",
            uri: "/-/package/private-lib/dist-tags",
            headers: "Host: registry.npmjs.org\r\nUser-Agent: npm/10.0.0",
            info: "npm registry request",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "npm.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R209_matches_npm_install_script_beacon()
    {
        var rule = new R209_NpmInstallScriptBeaconPatternRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.120",
            destination: "198.51.100.120",
            destinationPort: 443,
            host: "install-hook.example",
            method: "GET",
            uri: "/beacon?event=postinstall",
            headers: "Host: install-hook.example\r\nUser-Agent: npm/10.0.0",
            info: "postinstall npm_config_user_agent node -e beacon",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "node.exe")));

        var evt = AssertSingleEvent(result, "R209", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R209_ignores_normal_npm_download()
    {
        var rule = new R209_NpmInstallScriptBeaconPatternRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.121",
            destination: "104.16.30.34",
            destinationPort: 443,
            host: "registry.npmjs.org",
            method: "GET",
            uri: "/left-pad",
            headers: "Host: registry.npmjs.org\r\nUser-Agent: npm/10.0.0",
            info: "npm install left-pad",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "npm.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R210_matches_pypi_artifact_from_first_seen_host()
    {
        var rule = new R210_PypiPackageDownloadFromRareDomainRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.130",
            destination: "198.51.100.130",
            destinationPort: 443,
            host: "python-shadow.example",
            method: "GET",
            uri: "/packages/private-lib-1.0.0-py3-none-any.whl",
            headers: "Host: python-shadow.example\r\nUser-Agent: pip/24.0",
            info: "pip download",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "pip.exe")));

        var evt = AssertSingleEvent(result, "R210", SeverityLevel.Medium, 0.40);
        AssertEvidence(evt, "baseline.reason", "matched_conditions");
    }

    [Fact]
    public async Task R210_ignores_official_pythonhosted_download()
    {
        var rule = new R210_PypiPackageDownloadFromRareDomainRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.131",
            destination: "151.101.0.223",
            destinationPort: 443,
            host: "files.pythonhosted.org",
            method: "GET",
            uri: "/packages/private-lib-1.0.0-py3-none-any.whl",
            headers: "Host: files.pythonhosted.org\r\nUser-Agent: pip/24.0",
            info: "pip download",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "pip.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R211_matches_powershell_external_script_pull()
    {
        var rule = new R211_PowershellGalleryExternalScriptPullRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.140",
            destination: "198.51.100.140",
            destinationPort: 443,
            host: "scripts.evil.example",
            method: "GET",
            uri: "/bootstrap.ps1",
            headers: "Host: scripts.evil.example",
            info: "DownloadString IEX bootstrap",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "powershell.exe")));

        var evt = AssertSingleEvent(result, "R211", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R211_ignores_official_powershell_gallery_download()
    {
        var rule = new R211_PowershellGalleryExternalScriptPullRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.141",
            destination: "13.107.246.45",
            destinationPort: 443,
            host: "powershellgallery.com",
            method: "GET",
            uri: "/packages/MyModule.1.0.0.nupkg",
            headers: "Host: powershellgallery.com",
            info: "Install-Module MyModule",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "powershell.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R212_matches_curl_raw_script_to_shell()
    {
        var rule = new R212_CurlWgetRawScriptToShellRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.150",
            destination: "185.199.108.133",
            destinationPort: 443,
            host: "raw.githubusercontent.com",
            method: "GET",
            uri: "/org/repo/main/install.sh",
            headers: "Host: raw.githubusercontent.com\r\nUser-Agent: curl/8.7.1",
            info: "curl https://raw.githubusercontent.com/org/repo/main/install.sh | sh",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "curl.exe")));

        var evt = AssertSingleEvent(result, "R212", SeverityLevel.Critical, 0.60);
        AssertEvidence(evt, "matched_conditions");
    }

    [Fact]
    public async Task R212_ignores_raw_script_download_without_pipe_to_shell()
    {
        var rule = new R212_CurlWgetRawScriptToShellRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.151",
            destination: "185.199.108.133",
            destinationPort: 443,
            host: "raw.githubusercontent.com",
            method: "GET",
            uri: "/org/repo/main/install.sh",
            headers: "Host: raw.githubusercontent.com\r\nUser-Agent: curl/8.7.1",
            info: "curl https://raw.githubusercontent.com/org/repo/main/install.sh -O",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "curl.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R213_matches_mass_presigned_url_access()
    {
        var rule = new R213_CloudStoragePresignedUrlMassAccessRule();
        var baseTime = new DateTime(2026, 4, 30, 16, 20, 0, DateTimeKind.Utc);
        RuleEvaluationResult? last = null;
        for (var index = 0; index < 8; index++)
        {
            last = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
                source: "10.40.1.160",
                destination: "198.51.100.160",
                destinationPort: 443,
                host: "bucket.s3.amazonaws.com",
                method: "GET",
                uri: $"/archive/file{index}.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=cred{index}&X-Amz-Signature=sig{index}",
                headers: "Host: bucket.s3.amazonaws.com",
                info: "presigned download",
                service: "HTTPS",
                protocol: "HTTPS",
                process: "rclone.exe"), baseTime.AddSeconds(index * 10)));
        }

        var evt = AssertSingleEvent(last!, "R213", SeverityLevel.High, 0.40);
        AssertEvidence(evt, "cloud.provider", "count", "matched_conditions");
    }

    [Fact]
    public async Task R213_ignores_single_presigned_url_access()
    {
        var rule = new R213_CloudStoragePresignedUrlMassAccessRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.161",
            destination: "198.51.100.161",
            destinationPort: 443,
            host: "bucket.s3.amazonaws.com",
            method: "GET",
            uri: "/archive/file.zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=cred1&X-Amz-Signature=sig1",
            headers: "Host: bucket.s3.amazonaws.com",
            info: "presigned download",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "rclone.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R214_matches_s3_bucket_listing_request()
    {
        var rule = new R214_S3BucketListingProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.170",
            destination: "198.51.100.170",
            destinationPort: 443,
            host: "bucket.s3.amazonaws.com",
            method: "GET",
            uri: "/?list-type=2&prefix=logs/",
            headers: "Host: bucket.s3.amazonaws.com",
            info: "s3 list objects",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe")));

        var evt = AssertSingleEvent(result, "R214", SeverityLevel.Medium, 0.35);
        AssertEvidence(evt, "cloud.provider", "matched_conditions");
    }

    [Fact]
    public async Task R214_ignores_s3_object_download()
    {
        var rule = new R214_S3BucketListingProbeRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.171",
            destination: "198.51.100.171",
            destinationPort: 443,
            host: "bucket.s3.amazonaws.com",
            method: "GET",
            uri: "/logs/file.txt",
            headers: "Host: bucket.s3.amazonaws.com",
            info: "s3 object get",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R215_matches_azure_blob_container_listing()
    {
        var rule = new R215_AzureBlobContainerEnumerationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.180",
            destination: "198.51.100.180",
            destinationPort: 443,
            host: "tenant.blob.core.windows.net",
            method: "GET",
            uri: "/container?restype=container&comp=list",
            headers: "Host: tenant.blob.core.windows.net",
            info: "blob list",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe")));

        var evt = AssertSingleEvent(result, "R215", SeverityLevel.Medium, 0.35);
        AssertEvidence(evt, "cloud.provider", "matched_conditions");
    }

    [Fact]
    public async Task R215_ignores_blob_object_read()
    {
        var rule = new R215_AzureBlobContainerEnumerationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.181",
            destination: "198.51.100.181",
            destinationPort: 443,
            host: "tenant.blob.core.windows.net",
            method: "GET",
            uri: "/container/blob.txt",
            headers: "Host: tenant.blob.core.windows.net",
            info: "blob get",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R216_matches_gcs_bucket_listing()
    {
        var rule = new R216_GoogleStorageBucketEnumerationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.190",
            destination: "198.51.100.190",
            destinationPort: 443,
            host: "storage.googleapis.com",
            method: "GET",
            uri: "/storage/v1/b/my-bucket/o?prefix=logs/",
            headers: "Host: storage.googleapis.com",
            info: "gcs list objects",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe")));

        var evt = AssertSingleEvent(result, "R216", SeverityLevel.Medium, 0.35);
        AssertEvidence(evt, "cloud.provider", "matched_conditions");
    }

    [Fact]
    public async Task R216_ignores_gcs_media_object_download()
    {
        var rule = new R216_GoogleStorageBucketEnumerationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.191",
            destination: "198.51.100.191",
            destinationPort: 443,
            host: "storage.googleapis.com",
            method: "GET",
            uri: "/storage/v1/b/my-bucket/o/file.txt?alt=media",
            headers: "Host: storage.googleapis.com",
            info: "gcs object download",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe")));

        Assert.False(result.Matched);
    }

    [Fact]
    public async Task R217_matches_slack_webhook_exfiltration_pattern()
    {
        var rule = new R217_SlackWebhookExfiltrationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.200",
            destination: "13.107.6.175",
            destinationPort: 443,
            host: "hooks.slack.com",
            method: "POST",
            uri: "/services/T000/B000/SECRET",
            headers: "Host: hooks.slack.com\r\nContent-Type: application/json",
            info: "payload={\"text\":\"secret\"}",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "python.exe",
            length: 60_000)));

        var evt = AssertSingleEvent(result, "R217", SeverityLevel.High, 0.45);
        AssertEvidence(evt, "cloud.provider", "matched_conditions");
    }

    [Fact]
    public async Task R217_ignores_slack_desktop_client_post()
    {
        var rule = new R217_SlackWebhookExfiltrationRule();
        var result = await rule.EvaluateAsync(CreateContext(CreateWebRecord(
            source: "10.40.1.201",
            destination: "13.107.6.175",
            destinationPort: 443,
            host: "hooks.slack.com",
            method: "POST",
            uri: "/services/T000/B000/SECRET",
            headers: "Host: hooks.slack.com\r\nContent-Type: application/json",
            info: "payload={\"text\":\"hello\"}",
            service: "HTTPS",
            protocol: "HTTPS",
            process: "slack.exe",
            length: 60_000)));

        Assert.False(result.Matched);
    }

    [Fact]
    public void Migrated_clouddev_rules_register_rule_owned_precision_profiles()
    {
        _ = new R198_AwsMetadataCredentialRetrievalRule();
        _ = new R202_DockerRegistryPushPullAnomalyRule();
        _ = new R206_GitCloneFromUnknownExternalHostRule();
        _ = new R213_CloudStoragePresignedUrlMassAccessRule();
        _ = new R217_SlackWebhookExfiltrationRule();

        var r198 = RulePrecisionCatalog.GetProfile("R198", "CloudDev", SeverityLevel.Critical);
        var r202 = RulePrecisionCatalog.GetProfile("R202", "CloudDev", SeverityLevel.Medium);
        var r206 = RulePrecisionCatalog.GetProfile("R206", "CloudDev", SeverityLevel.Medium);
        var r213 = RulePrecisionCatalog.GetProfile("R213", "CloudDev", SeverityLevel.High);
        var r217 = RulePrecisionCatalog.GetProfile("R217", "CloudDev", SeverityLevel.High);

        Assert.Equal(RuleRuntimeMode.Alert, r198.DefaultMode);
        Assert.Equal(6, r202.Threshold);
        Assert.Contains(RuleTelemetryKind.DevOpsAudit, r206.RequiredTelemetry);
        Assert.Equal(8, r213.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, r217.DefaultMode);
    }

    private static RuleEvaluationContext CreateContext(TrafficRecord record, DateTime? timestampUtc = null)
        => new(record, Sensitivity.Balanced, timestampUtc ?? new DateTime(2026, 4, 30, 15, 0, 0, DateTimeKind.Utc));

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
        int length = 2048)
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
            Info = info,
            ProcessName = process,
            IsTcp = true,
            Length = length,
            L4Len = length
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
