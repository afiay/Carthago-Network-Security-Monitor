// SPDX-License-Identifier: MIT
// File: Engine/Rules/ExtendedRuleDetectors.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Baseline;
using Carthago.Engine.PayloadNormalization;

namespace Carthago.Engine.Rules
{
    /// <summary>
    /// Research-backed R057-R544 telemetry detectors.
    /// These rules intentionally use only fields already present in TrafficRecord. If a field is absent,
    /// the detector returns NoMatch; it never fabricates demo detections.
    /// </summary>
    internal static class ExtendedRuleDetectors
    {
        private static readonly TimeSpan DefaultWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan LongWindow = TimeSpan.FromMinutes(30);

        private static readonly ConcurrentDictionary<string, DateTime> SeenDeviceKeys = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> SeenMacVendors = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> MacToIps = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> IpToMacs = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> SrcToDestinations = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> SrcToAsns = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> SrcToCountries = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<int, DateTime>> InternalHostServices = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> ServerLikeSources = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, List<DateTime>> PerKeyTimes = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> PerKeyDistinct = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, List<(DateTime Ts, int Bytes)>> ByteWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, List<DateTime>> DnsIntervals = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> DomainSubLabels = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> SeenDomains = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> RecentInternalSweepBySource = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, (long OutBytes, long InBytes, DateTime LastSeen)> UploadRatioByHost = new(StringComparer.OrdinalIgnoreCase);


        private sealed class ExpansionRuleSpec
        {
            public ExpansionRuleSpec(string ruleId, string summary, SeverityLevel severity)
            {
                RuleId = ruleId;
                Summary = summary;
                Severity = severity;
            }

            public string RuleId { get; }
            public string Summary { get; }
            public SeverityLevel Severity { get; }
            public string[] AnyText { get; init; } = Array.Empty<string>();
            public string[] AllText { get; init; } = Array.Empty<string>();
            public string[] HostText { get; init; } = Array.Empty<string>();
            public string[] Protocols { get; init; } = Array.Empty<string>();
            public string[] DnsQtypes { get; init; } = Array.Empty<string>();
            public int[] Ports { get; init; } = Array.Empty<int>();
            public bool RequireInternalSource { get; init; }
            public bool RequireExternalDestination { get; init; }
            public bool RequireHttp { get; init; }
            public bool RequireDns { get; init; }
            public bool RequireTls { get; init; }
            public bool RequireUdp { get; init; }
            public bool RequireTcp { get; init; }
            public bool RequireHighEntropyHost { get; init; }
            public bool RequireHighEntropyUri { get; init; }
            public bool RequireBaselineFirstSeen { get; init; }
            public int Threshold { get; init; }
            public int WindowSeconds { get; init; } = 300;
            public string? DistinctField { get; init; }
            public string Scope { get; init; } = "source";
            public int MinimumUriLength { get; init; }
        }

        private static readonly IReadOnlyDictionary<string, ExpansionRuleSpec> ExpansionRuleSpecs = new Dictionary<string, ExpansionRuleSpec>(StringComparer.OrdinalIgnoreCase)
        {
                ["R123"] = new ExpansionRuleSpec("R123", "Suspicious VPN Login Path", SeverityLevel.High) { AnyText = new[] { "vpn", "login", "auth", "saml", "oauth" }, Ports = new[] { 443, 8443, 9443 }, RequireExternalDestination = true, RequireHttp = true },
                ["R124"] = new ExpansionRuleSpec("R124", "External RDP Exposure Attempt", SeverityLevel.High) { AnyText = new[] { "rdp", "remote desktop", "mstsc" }, Ports = new[] { 3389 } },
                ["R125"] = new ExpansionRuleSpec("R125", "External WinRM Exposure Attempt", SeverityLevel.High) { AnyText = new[] { "winrm", "wsman", "powershell remoting" }, Ports = new[] { 5985, 5986 } },
                ["R126"] = new ExpansionRuleSpec("R126", "External SSH Brute Candidate", SeverityLevel.High) { AnyText = new[] { "failed", "invalid user", "authentication failed", "ssh" }, Ports = new[] { 22 }, Threshold = 8, WindowSeconds = 120, Scope = "source-destination" },
                ["R127"] = new ExpansionRuleSpec("R127", "Admin Portal Access From Internet", SeverityLevel.High) { AnyText = new[] { "/admin", "/administrator", "/wp-admin", "/login", "admin portal", "manager/html" }, RequireExternalDestination = true, RequireHttp = true },
                ["R128"] = new ExpansionRuleSpec("R128", "Network Appliance Management Exposure", SeverityLevel.High) { AnyText = new[] { "fortinet", "fortigate", "globalprotect", "anyconnect", "pulse secure", "netscaler", "citrix adc", "sonicwall", "vpn portal" }, RequireExternalDestination = true, RequireHttp = true },
                ["R129"] = new ExpansionRuleSpec("R129", "Suspicious SAML OIDC Callback Traffic", SeverityLevel.Medium) { AnyText = new[] { "samlresponse", "samlrequest", "openid", "oauth", "callback", "redirect_uri", "id_token" }, RequireHttp = true },
                ["R130"] = new ExpansionRuleSpec("R130", "Credential Stuffing Against Web Login", SeverityLevel.High) { AnyText = new[] { "login", "signin", "password", "credential" }, RequireHttp = true, Threshold = 20, Scope = "source-destination" },
                ["R131"] = new ExpansionRuleSpec("R131", "HTTP Authentication Failure Spike", SeverityLevel.Medium) { AnyText = new[] { "401", "403", "unauthorized", "forbidden", "authentication failed", "invalid password" }, RequireHttp = true, Threshold = 15, Scope = "source-destination" },
                ["R132"] = new ExpansionRuleSpec("R132", "Rapid Country Change For Source Identity", SeverityLevel.Medium) { AnyText = new[] { "login", "auth", "signin" }, Threshold = 3, WindowSeconds = 600, DistinctField = "country" },
                ["R133"] = new ExpansionRuleSpec("R133", "Basic Authentication Over Cleartext", SeverityLevel.High) { AnyText = new[] { "authorization: basic", "basic " }, RequireHttp = true },
                ["R134"] = new ExpansionRuleSpec("R134", "API Token In URL Query", SeverityLevel.High) { AnyText = new[] { "api_key=", "apikey=", "access_token=", "token=", "client_secret=", "secret=" }, RequireHttp = true },
                ["R135"] = new ExpansionRuleSpec("R135", "Bearer Token Over Cleartext HTTP", SeverityLevel.High) { AnyText = new[] { "authorization: bearer", "bearer " }, RequireHttp = true },
                ["R136"] = new ExpansionRuleSpec("R136", "Session Cookie Over Cleartext HTTP", SeverityLevel.Medium) { AnyText = new[] { "cookie:", "sessionid=", "php session", "jsessionid", "asp.net_sessionid" }, RequireHttp = true },
                ["R137"] = new ExpansionRuleSpec("R137", "Password Reset Or Enrollment Spike", SeverityLevel.Medium) { AnyText = new[] { "reset password", "forgot password", "password-reset", "enroll", "mfa", "totp", "webauthn" }, RequireHttp = true, Threshold = 8, Scope = "source-destination" },
                ["R138"] = new ExpansionRuleSpec("R138", "Self-Signed Certificate To External Host", SeverityLevel.Medium) { AnyText = new[] { "self-signed", "self signed" }, RequireExternalDestination = true, RequireTls = true },
                ["R139"] = new ExpansionRuleSpec("R139", "Weak TLS Version Observed", SeverityLevel.High) { AnyText = new[] { "tls 1.0", "tls1.0", "tls 1.1", "tls1.1", "ssl3", "ssl 3" }, RequireTls = true },
                ["R140"] = new ExpansionRuleSpec("R140", "Suspicious Certificate Issuer Pattern", SeverityLevel.Medium) { AnyText = new[] { "issuer=unknown", "issuer=localhost", "issuer=default", "snakeoil", "test ca", "mitmproxy" }, RequireTls = true },
                ["R141"] = new ExpansionRuleSpec("R141", "New SNI With Rare TLS Fingerprint", SeverityLevel.Medium) { AnyText = new[] { "ja3", "ja4", "rare", "new sni" }, RequireTls = true, Threshold = 3, WindowSeconds = 900, DistinctField = "host" },
                ["R142"] = new ExpansionRuleSpec("R142", "TLS Certificate Subject SNI Mismatch", SeverityLevel.Medium) { AnyText = new[] { "certificate mismatch", "name mismatch", "subject mismatch", "sni mismatch" }, RequireTls = true },
                ["R143"] = new ExpansionRuleSpec("R143", "Wildcard Certificate On Sensitive Service", SeverityLevel.Medium) { AnyText = new[] { "*.", "wildcard" }, Ports = new[] { 3389, 5985, 5986, 445, 389, 636, 1433, 3306, 5432 }, RequireTls = true },
                ["R144"] = new ExpansionRuleSpec("R144", "Certificate Validity Period Too Long", SeverityLevel.Medium) { AnyText = new[] { "validity too long", "notafter", "certificate valid" }, RequireTls = true },
                ["R145"] = new ExpansionRuleSpec("R145", "Short-Lived Certificate With New SNI", SeverityLevel.Medium) { AnyText = new[] { "short lived", "short-lived", "new certificate", "new sni" }, RequireTls = true, Threshold = 3, WindowSeconds = 900, DistinctField = "host" },
                ["R146"] = new ExpansionRuleSpec("R146", "TLS Handshake Failure Spike", SeverityLevel.Medium) { AnyText = new[] { "handshake failure", "tls alert", "bad certificate", "unknown ca" }, RequireTls = true, Threshold = 12, Scope = "source-destination" },
                ["R147"] = new ExpansionRuleSpec("R147", "Encrypted ClientHello Or ECH Indicator", SeverityLevel.Low) { AnyText = new[] { "encrypted client hello", "ech", "encrypted_client_hello" }, RequireTls = true },
                ["R148"] = new ExpansionRuleSpec("R148", "TLS To Dynamic DNS Host", SeverityLevel.Medium) { HostText = new[] { "duckdns", "no-ip", "dynu", "hopto", "ddns", "serveo", "ngrok" }, RequireExternalDestination = true, RequireTls = true },
                ["R149"] = new ExpansionRuleSpec("R149", "IP Literal Used As TLS Name", SeverityLevel.Medium) { AnyText = new[] { "sni=ip", "ip literal", "tls to ip literal" }, RequireTls = true },
                ["R150"] = new ExpansionRuleSpec("R150", "Known Malware-Like TLS Fingerprint Label", SeverityLevel.High) { AnyText = new[] { "malware ja3", "malware ja4", "cobalt strike ja3", "sliver ja3", "meterpreter ja3" }, RequireTls = true },
                ["R151"] = new ExpansionRuleSpec("R151", "HTTP2 ALPN On Uncommon Port", SeverityLevel.Medium) { AnyText = new[] { "h2", "http/2" }, Ports = new[] { 8081, 8444, 9443, 10443, 5001 }, RequireTls = true },
                ["R152"] = new ExpansionRuleSpec("R152", "TLS Fingerprint Fan-Out To Many ASNs", SeverityLevel.Medium) { AnyText = new[] { "ja3", "ja4", "tls" }, RequireTls = true, Threshold = 5, WindowSeconds = 900, DistinctField = "asn" },
                ["R153"] = new ExpansionRuleSpec("R153", "GraphQL Introspection Query", SeverityLevel.Medium) { AnyText = new[] { "__schema", "__typename", "introspectionquery", "graphql" }, RequireHttp = true },
                ["R154"] = new ExpansionRuleSpec("R154", "GraphQL Batching Abuse", SeverityLevel.Medium) { AnyText = new[] { "graphql", "[", "]", "operationname" }, RequireHttp = true, Threshold = 15, WindowSeconds = 120, Scope = "source-destination" },
                ["R155"] = new ExpansionRuleSpec("R155", "REST API Enumeration Burst", SeverityLevel.Medium) { AnyText = new[] { "/api/", "/v1/", "/v2/", "/users", "/accounts", "/objects" }, RequireHttp = true, Threshold = 30, WindowSeconds = 180, DistinctField = "uri", Scope = "source-destination" },
                ["R156"] = new ExpansionRuleSpec("R156", "JWT None Algorithm Indicator", SeverityLevel.High) { AnyText = new[] { "\"alg\":\"none\"", "alg:none", "eyjhbGciOiJub25l" }, RequireHttp = true },
                ["R157"] = new ExpansionRuleSpec("R157", "JWT In URL Query", SeverityLevel.Medium) { AnyText = new[] { "jwt=", "id_token=", "eyJhbGci", "eyjhbGci" }, RequireHttp = true },
                ["R158"] = new ExpansionRuleSpec("R158", "Swagger OpenAPI Exposure Probe", SeverityLevel.Medium) { AnyText = new[] { "swagger.json", "swagger-ui", "openapi.json", "api-docs" }, RequireHttp = true },
                ["R159"] = new ExpansionRuleSpec("R159", "Spring Actuator Exposure Probe", SeverityLevel.High) { AnyText = new[] { "/actuator/env", "/actuator/heapdump", "/actuator/jolokia", "/actuator/metrics" }, RequireHttp = true },
                ["R160"] = new ExpansionRuleSpec("R160", "Kubernetes API Probe", SeverityLevel.High) { AnyText = new[] { "/api/v1/namespaces", "/apis/apps", "kubernetes", "serviceaccounts" }, Ports = new[] { 6443, 8443, 443 }, RequireHttp = true },
                ["R161"] = new ExpansionRuleSpec("R161", "Docker API TCP Exposure Probe", SeverityLevel.High) { AnyText = new[] { "/containers/json", "/images/json", "/version", "docker" }, Ports = new[] { 2375, 2376 }, RequireHttp = true },
                ["R162"] = new ExpansionRuleSpec("R162", "Redis Memcached Web Probe", SeverityLevel.Medium) { AnyText = new[] { "redis", "memcached", "stats", "flush_all" }, Ports = new[] { 6379, 11211 }, RequireHttp = true },
                ["R163"] = new ExpansionRuleSpec("R163", "SSRF Metadata Service Probe", SeverityLevel.Critical) { AnyText = new[] { "169.254.169.254", "metadata.google.internal", "metadata/identity/oauth2/token", "latest/meta-data", "iam/security-credentials" }, RequireHttp = true },
                ["R164"] = new ExpansionRuleSpec("R164", "Open Redirect Parameter Abuse", SeverityLevel.Medium) { AnyText = new[] { "redirect=", "redirect_uri=", "returnurl=", "next=http", "url=http", "continue=http" }, RequireHttp = true },
                ["R165"] = new ExpansionRuleSpec("R165", "PHPInfo Exposure Probe", SeverityLevel.Low) { AnyText = new[] { "phpinfo.php", "?phpinfo", "phpinfo()" }, RequireHttp = true },
                ["R166"] = new ExpansionRuleSpec("R166", "Environment File Secret Probe", SeverityLevel.High) { AnyText = new[] { "/.env", "/.aws/credentials", "/config.json", "database_url", "aws_secret_access_key" }, RequireHttp = true },
                ["R167"] = new ExpansionRuleSpec("R167", "Git Directory Exposure Probe", SeverityLevel.High) { AnyText = new[] { "/.git/config", "/.git/HEAD", "/.git/index" }, RequireHttp = true },
                ["R168"] = new ExpansionRuleSpec("R168", "Backup Archive Download Probe", SeverityLevel.Medium) { AnyText = new[] { ".bak", ".backup", ".zip", ".tar.gz", ".sql.gz", "db_backup", "backup" }, RequireHttp = true },
                ["R169"] = new ExpansionRuleSpec("R169", "Admin Login Brute Indicator", SeverityLevel.Medium) { AnyText = new[] { "/admin/login", "/wp-login.php", "/user/login", "/manager/html" }, RequireHttp = true, Threshold = 12, Scope = "source-destination" },
                ["R170"] = new ExpansionRuleSpec("R170", "XXE Payload Indicator", SeverityLevel.High) { AnyText = new[] { "<!doctype", "<!entity", "system \"file://", "xxe", "/etc/passwd" }, RequireHttp = true },
                ["R171"] = new ExpansionRuleSpec("R171", "SOAP Action Exploit Pattern", SeverityLevel.Medium) { AnyText = new[] { "soapaction", "wsdl", "<soapenv", "<soap:envelope" }, RequireHttp = true },
                ["R172"] = new ExpansionRuleSpec("R172", "Scanner User Agent With Browser Claim Mismatch", SeverityLevel.Low) { AnyText = new[] { "sqlmap", "nikto", "nuclei", "gobuster", "dirbuster", "ffuf", "zgrab" }, RequireHttp = true },
                ["R173"] = new ExpansionRuleSpec("R173", "Suspicious CORS Preflight To Admin API", SeverityLevel.Medium) { AnyText = new[] { "OPTIONS", "access-control-request-method", "/admin", "/api/" }, RequireHttp = true },
                ["R174"] = new ExpansionRuleSpec("R174", "WebDAV Method Abuse", SeverityLevel.Medium) { AnyText = new[] { "PROPFIND", "PROPPATCH", "MKCOL", "LOCK", "UNLOCK", "MOVE", "COPY" }, RequireHttp = true },
                ["R175"] = new ExpansionRuleSpec("R175", "HTTP Request Smuggling Indicator", SeverityLevel.High) { AnyText = new[] { "transfer-encoding: chunked", "content-length:", "cl.te", "te.cl", "chunked" }, RequireHttp = true },
                ["R176"] = new ExpansionRuleSpec("R176", "Host Header Injection Indicator", SeverityLevel.Medium) { AnyText = new[] { "x-forwarded-host", "x-original-url", "x-rewrite-url", "host: 127.0.0.1", "host: localhost" }, RequireHttp = true },
                ["R177"] = new ExpansionRuleSpec("R177", "High-Risk File Upload Extension", SeverityLevel.High) { AnyText = new[] { ".jsp", ".aspx", ".php", ".war", ".jspx", ".phtml", "multipart/form-data" }, RequireHttp = true },
                ["R178"] = new ExpansionRuleSpec("R178", "DNS Query For Crypto Mining Pool", SeverityLevel.High) { HostText = new[] { "minexmr", "nanopool", "ethermine", "nicehash", "monerohash", "xmrpool", "2miners" }, RequireDns = true },
                ["R179"] = new ExpansionRuleSpec("R179", "DNS Query For Tor Onion Gateway", SeverityLevel.Medium) { HostText = new[] { ".onion", "tor2web", "onion.to", "onion.city" }, RequireDns = true },
                ["R180"] = new ExpansionRuleSpec("R180", "DNS Query To High-Risk TLD", SeverityLevel.Low) { HostText = new[] { ".zip", ".mov", ".top", ".xyz", ".click", ".country", ".gq", ".tk" }, RequireDns = true },
                ["R181"] = new ExpansionRuleSpec("R181", "Excessive DNS ANY Queries", SeverityLevel.Medium) { DnsQtypes = new[] { "ANY" }, RequireDns = true, Threshold = 10 },
                ["R182"] = new ExpansionRuleSpec("R182", "DNS Zone Transfer Attempt", SeverityLevel.High) { DnsQtypes = new[] { "AXFR", "IXFR" }, RequireDns = true },
                ["R183"] = new ExpansionRuleSpec("R183", "DNSSEC Random Subdomain Spike", SeverityLevel.Medium) { DnsQtypes = new[] { "DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3" }, RequireDns = true, Threshold = 20, DistinctField = "host" },
                ["R184"] = new ExpansionRuleSpec("R184", "External Reverse DNS Enumeration", SeverityLevel.Medium) { HostText = new[] { "in-addr.arpa", "ip6.arpa" }, RequireDns = true, Threshold = 30, DistinctField = "host" },
                ["R185"] = new ExpansionRuleSpec("R185", "Canary Or Metadata Domain Probe", SeverityLevel.Low) { HostText = new[] { "canarytokens", "burpcollaborator", "interactsh", "oastify", "requestbin" }, RequireDns = true },
                ["R186"] = new ExpansionRuleSpec("R186", "DNS CAA Record Probing Burst", SeverityLevel.Low) { DnsQtypes = new[] { "CAA" }, RequireDns = true, Threshold = 15 },
                ["R187"] = new ExpansionRuleSpec("R187", "DNS NULL Query Usage", SeverityLevel.Medium) { DnsQtypes = new[] { "NULL" }, RequireDns = true },
                ["R188"] = new ExpansionRuleSpec("R188", "Active Directory SRV Enumeration", SeverityLevel.Medium) { HostText = new[] { "_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_kpasswd._tcp" }, RequireDns = true },
                ["R189"] = new ExpansionRuleSpec("R189", "AD SRV Query To External Resolver", SeverityLevel.High) { HostText = new[] { "_ldap._tcp", "_kerberos._tcp", "_gc._tcp" }, RequireExternalDestination = true, RequireDns = true },
                ["R190"] = new ExpansionRuleSpec("R190", "DNS Short TTL Burst", SeverityLevel.Medium) { AnyText = new[] { "ttl=0", "ttl 0", "ttl=1", "ttl 1" }, RequireDns = true, Threshold = 10, Scope = "source-destination" },
                ["R191"] = new ExpansionRuleSpec("R191", "Consonant-Heavy DGA Domain", SeverityLevel.Medium) { RequireDns = true, RequireHighEntropyHost = true },
                ["R192"] = new ExpansionRuleSpec("R192", "Punycode Homograph Domain", SeverityLevel.Medium) { HostText = new[] { "xn--" }, RequireDns = true },
                ["R193"] = new ExpansionRuleSpec("R193", "Cloud Brand Lookalike Domain", SeverityLevel.Medium) { HostText = new[] { "micros0ft", "rnicrosoft", "g00gle", "amaz0n", "cloudfIare", "paypaI", "appIe" }, RequireDns = true },
                ["R194"] = new ExpansionRuleSpec("R194", "DoH Over Uncommon Host", SeverityLevel.Medium) { HostText = new[] { "dns-query" }, RequireExternalDestination = true, RequireHttp = true },
                ["R195"] = new ExpansionRuleSpec("R195", "DNS Over TLS To Unapproved Resolver", SeverityLevel.High) { Ports = new[] { 853 }, RequireExternalDestination = true },
                ["R196"] = new ExpansionRuleSpec("R196", "NXDOMAIN Unique Root Spike", SeverityLevel.Medium) { AnyText = new[] { "nxdomain" }, RequireDns = true, Threshold = 20, DistinctField = "host" },
                ["R197"] = new ExpansionRuleSpec("R197", "DNS Rebinding Private IP Answer", SeverityLevel.High) { AnyText = new[] { "192.168.", "10.", "172.16.", "127.0.0.1", "::1", "fc00:", "fd00:" }, RequireDns = true },
                ["R198"] = new ExpansionRuleSpec("R198", "AWS Metadata Credential Retrieval", SeverityLevel.Critical) { AnyText = new[] { "169.254.169.254", "latest/meta-data/iam/security-credentials", "x-aws-ec2-metadata-token" }, RequireHttp = true },
                ["R199"] = new ExpansionRuleSpec("R199", "GCP Metadata Credential Retrieval", SeverityLevel.Critical) { AnyText = new[] { "metadata.google.internal", "computeMetadata/v1", "metadata-flavor: google" }, RequireHttp = true },
                ["R200"] = new ExpansionRuleSpec("R200", "Azure Metadata Credential Retrieval", SeverityLevel.Critical) { AnyText = new[] { "metadata/identity/oauth2/token", "api-version=2018-02-01", "metadata:true" }, RequireHttp = true },
                ["R201"] = new ExpansionRuleSpec("R201", "Kubernetes Service Account Token Access", SeverityLevel.Critical) { AnyText = new[] { "/var/run/secrets/kubernetes.io/serviceaccount/token", "serviceaccount/token", "bearer kubernetes" }, RequireHttp = true },
                ["R202"] = new ExpansionRuleSpec("R202", "Docker Registry Push Pull Anomaly", SeverityLevel.Medium) { AnyText = new[] { "/v2/", "docker-registry", "manifest", "blobs/uploads" }, RequireHttp = true, Threshold = 20, Scope = "source-destination" },
                ["R203"] = new ExpansionRuleSpec("R203", "Container Image Layer Bulk Download", SeverityLevel.Medium) { AnyText = new[] { "/blobs/sha256", "docker-content-digest", "application/vnd.docker" }, RequireHttp = true, Threshold = 30, WindowSeconds = 600, Scope = "source-destination" },
                ["R204"] = new ExpansionRuleSpec("R204", "Terraform State File Access", SeverityLevel.High) { AnyText = new[] { "terraform.tfstate", "tfstate", "backend.tf", "statefile" }, RequireHttp = true },
                ["R205"] = new ExpansionRuleSpec("R205", "CI CD Secret Token In URL", SeverityLevel.High) { AnyText = new[] { "gitlab-ci-token", "github_token", "circle_token", "jenkins", "buildkite", "ci_job_token" }, RequireHttp = true },
                ["R206"] = new ExpansionRuleSpec("R206", "Git Clone From Unknown External Host", SeverityLevel.Medium) { AnyText = new[] { "git-upload-pack", "git clone", "/info/refs?service=git-upload-pack" }, RequireExternalDestination = true, RequireHttp = true },
                ["R207"] = new ExpansionRuleSpec("R207", "Git Push To Unknown External Host", SeverityLevel.High) { AnyText = new[] { "git-receive-pack", "/info/refs?service=git-receive-pack" }, RequireExternalDestination = true, RequireHttp = true },
                ["R208"] = new ExpansionRuleSpec("R208", "Package Manager To Suspicious Registry", SeverityLevel.Medium) { AnyText = new[] { "npm", "pip", "pypi", "nuget", "maven", "rubygems", "registry" }, RequireExternalDestination = true, RequireHttp = true },
                ["R209"] = new ExpansionRuleSpec("R209", "NPM Install Script Beacon Pattern", SeverityLevel.High) { AnyText = new[] { "postinstall", "preinstall", "node -e", "npm_config", "package.json" }, RequireHttp = true },
                ["R210"] = new ExpansionRuleSpec("R210", "PyPI Package Download From Rare Domain", SeverityLevel.Medium) { HostText = new[] { "pypi", "pythonhosted", "files.pythonhosted" }, RequireHttp = true, Threshold = 8, WindowSeconds = 600, DistinctField = "host" },
                ["R211"] = new ExpansionRuleSpec("R211", "PowerShell Gallery External Script Pull", SeverityLevel.High) { AnyText = new[] { "powershellgallery", "install-module", "downloadstring", "iex" }, RequireHttp = true },
                ["R212"] = new ExpansionRuleSpec("R212", "Curl Wget Raw Script To Shell", SeverityLevel.Critical) { AnyText = new[] { "curl ", "wget ", "| sh", "| bash", "raw.githubusercontent.com", "gist.githubusercontent.com" }, RequireHttp = true },
                ["R213"] = new ExpansionRuleSpec("R213", "Cloud Storage Presigned URL Mass Access", SeverityLevel.High) { AnyText = new[] { "x-amz-signature", "x-amz-security-token", "sig=", "se=", "sp=", "x-goog-signature" }, RequireHttp = true, Threshold = 10 },
                ["R214"] = new ExpansionRuleSpec("R214", "S3 Bucket Listing Probe", SeverityLevel.Medium) { AnyText = new[] { "list-type=2", "?prefix=", "x-amz-bucket", "s3.amazonaws.com" }, RequireHttp = true },
                ["R215"] = new ExpansionRuleSpec("R215", "Azure Blob Container Enumeration", SeverityLevel.Medium) { AnyText = new[] { "comp=list", "restype=container", "blob.core.windows.net" }, RequireHttp = true },
                ["R216"] = new ExpansionRuleSpec("R216", "Google Storage Bucket Enumeration", SeverityLevel.Medium) { AnyText = new[] { "storage.googleapis.com", "/storage/v1/b/", "alt=media" }, RequireHttp = true },
                ["R217"] = new ExpansionRuleSpec("R217", "Slack Webhook Exfiltration", SeverityLevel.High) { HostText = new[] { "hooks.slack.com", "slack.com/api/files.upload", "slack.com/api/chat.postMessage" }, RequireHttp = true },
                ["R218"] = new ExpansionRuleSpec("R218", "Discord Webhook File Upload", SeverityLevel.High) { HostText = new[] { "discord.com/api/webhooks", "discordapp.com/api/webhooks" }, RequireHttp = true },
                ["R219"] = new ExpansionRuleSpec("R219", "Telegram Bot API Send Document", SeverityLevel.High) { AnyText = new[] { "senddocument", "sendmessage", "sendphoto" }, HostText = new[] { "api.telegram.org" }, RequireHttp = true },
                ["R220"] = new ExpansionRuleSpec("R220", "Paste Service High Volume POST", SeverityLevel.High) { AnyText = new[] { "POST" }, HostText = new[] { "pastebin", "hastebin", "ghostbin", "rentry", "paste.ee" }, RequireHttp = true, Threshold = 5 },
                ["R221"] = new ExpansionRuleSpec("R221", "Remote Desktop SaaS Tool Beacon", SeverityLevel.Medium) { HostText = new[] { "anydesk", "teamviewer", "screenconnect", "connectwise", "splashtop", "rustdesk", "tailscale", "zerotier" }, RequireExternalDestination = true },
                ["R222"] = new ExpansionRuleSpec("R222", "Unauthorized Overlay Network Egress", SeverityLevel.High) { HostText = new[] { "tailscale", "zerotier", "ngrok", "cloudflared", "trycloudflare", "wireguard" }, RequireExternalDestination = true },
                ["R223"] = new ExpansionRuleSpec("R223", "ICS Protocol To Internet", SeverityLevel.Critical) { Ports = new[] { 102, 502, 20000, 44818, 4840, 47808, 1962, 2404 }, RequireExternalDestination = true },
                ["R224"] = new ExpansionRuleSpec("R224", "DNP3 Traffic Outside Approved Segment", SeverityLevel.High) { Ports = new[] { 20000 }, RequireExternalDestination = true },
                ["R225"] = new ExpansionRuleSpec("R225", "S7comm Traffic Outside Approved Segment", SeverityLevel.High) { Ports = new[] { 102 }, RequireExternalDestination = true },
                ["R226"] = new ExpansionRuleSpec("R226", "EtherNetIP CIP Discovery Burst", SeverityLevel.Medium) { AnyText = new[] { "cip", "ethernet/ip", "listidentity" }, Ports = new[] { 44818 }, Threshold = 8, WindowSeconds = 120 },
                ["R227"] = new ExpansionRuleSpec("R227", "Profinet DCP Discovery Suspicious", SeverityLevel.Medium) { AnyText = new[] { "profinet", "dcp", "identify all" }, Ports = new[] { 34964 }, Threshold = 8, WindowSeconds = 120 },
                ["R228"] = new ExpansionRuleSpec("R228", "OPC UA Internet Egress", SeverityLevel.High) { AnyText = new[] { "opc ua", "opc.tcp" }, Ports = new[] { 4840 }, RequireExternalDestination = true },
                ["R229"] = new ExpansionRuleSpec("R229", "MQTT Retained Topic Abuse", SeverityLevel.Medium) { AnyText = new[] { "retain", "retained" }, Ports = new[] { 1883, 8883 } },
                ["R230"] = new ExpansionRuleSpec("R230", "MQTT Last Will Suspicious", SeverityLevel.Medium) { AnyText = new[] { "last will", "will topic", "will message" }, Ports = new[] { 1883, 8883 } },
                ["R231"] = new ExpansionRuleSpec("R231", "CoAP Multicast Discovery Burst", SeverityLevel.Medium) { AnyText = new[] { "coap", "/.well-known/core" }, Ports = new[] { 5683, 5684 }, Threshold = 10, WindowSeconds = 120 },
                ["R232"] = new ExpansionRuleSpec("R232", "mDNS Service Enumeration Burst", SeverityLevel.Medium) { AnyText = new[] { "_services._dns-sd._udp", "mdns", "bonjour" }, Ports = new[] { 5353 }, Threshold = 20, WindowSeconds = 120 },
                ["R233"] = new ExpansionRuleSpec("R233", "Printer Admin Protocol External Access", SeverityLevel.Medium) { AnyText = new[] { "ipp", "printer", "jetdirect", "pjl" }, Ports = new[] { 631, 9100, 515 }, RequireExternalDestination = true },
                ["R234"] = new ExpansionRuleSpec("R234", "IP Camera RTSP External Stream", SeverityLevel.High) { AnyText = new[] { "rtsp", "camera", "nvr", "rtsp://" }, Ports = new[] { 554, 8554 }, RequireExternalDestination = true },
                ["R235"] = new ExpansionRuleSpec("R235", "ONVIF Discovery From Workstation", SeverityLevel.Medium) { AnyText = new[] { "onvif", "probe", "ws-discovery" }, Ports = new[] { 3702 }, Threshold = 8, WindowSeconds = 120 },
                ["R236"] = new ExpansionRuleSpec("R236", "IoT Firmware Update Over Cleartext", SeverityLevel.High) { AnyText = new[] { "firmware", "upgrade", "update.bin", ".bin" }, RequireHttp = true },
                ["R237"] = new ExpansionRuleSpec("R237", "IoT Default Web Admin Access", SeverityLevel.High) { AnyText = new[] { "admin:admin", "admin/password", "default password", "/login.cgi", "/goform/" }, RequireHttp = true },
                ["R238"] = new ExpansionRuleSpec("R238", "Smart Home Hub Cloud Burst", SeverityLevel.Medium) { HostText = new[] { "tuya", "smartthings", "philips-hue", "aqara", "eufy", "xiaomi", "home-assistant" }, Threshold = 30 },
                ["R239"] = new ExpansionRuleSpec("R239", "Zigbee2MQTT Bridge Internet Access", SeverityLevel.High) { AnyText = new[] { "zigbee2mqtt", "z2m" }, Ports = new[] { 1883, 8883 }, RequireExternalDestination = true },
                ["R240"] = new ExpansionRuleSpec("R240", "Modbus Write Function", SeverityLevel.Critical) { AnyText = new[] { "write single register", "write multiple registers", "function 5", "function 6", "function 15", "function 16" }, Ports = new[] { 502 } },
                ["R241"] = new ExpansionRuleSpec("R241", "BACnet Who-Is I-Am Burst", SeverityLevel.Medium) { AnyText = new[] { "who-is", "i-am", "bacnet" }, Ports = new[] { 47808 }, Threshold = 10, WindowSeconds = 120 },
                ["R242"] = new ExpansionRuleSpec("R242", "NTP Amplification Candidate", SeverityLevel.Medium) { AnyText = new[] { "monlist", "ntpdc", "mode 7" }, Ports = new[] { 123 }, RequireUdp = true, Threshold = 20, WindowSeconds = 120, Scope = "source-destination" },
                ["R243"] = new ExpansionRuleSpec("R243", "Large Outbound Archive Transfer", SeverityLevel.High) { AnyText = new[] { ".zip", ".7z", ".rar", ".tar.gz", ".tgz" }, RequireExternalDestination = true, MinimumUriLength = 40 },
                ["R244"] = new ExpansionRuleSpec("R244", "Database Dump Filename Transfer", SeverityLevel.Critical) { AnyText = new[] { "dump.sql", "db.sql", "database.sql", "backup.sql", ".sql.gz" }, RequireExternalDestination = true },
                ["R245"] = new ExpansionRuleSpec("R245", "Sensitive File Extension Upload", SeverityLevel.High) { AnyText = new[] { ".pem", ".pfx", ".key", ".kdbx", ".ovpn", ".rdp", ".docx", ".xlsx" }, RequireExternalDestination = true },
                ["R246"] = new ExpansionRuleSpec("R246", "Source Code Archive Upload", SeverityLevel.High) { AnyText = new[] { "src.zip", "source.zip", "repo.zip", ".git.zip", "project.tar.gz" }, RequireExternalDestination = true },
                ["R247"] = new ExpansionRuleSpec("R247", "SSH SCP High Volume Egress", SeverityLevel.High) { AnyText = new[] { "scp", "sftp", "ssh" }, Ports = new[] { 22 }, RequireExternalDestination = true, Threshold = 20, Scope = "source-destination" },
                ["R248"] = new ExpansionRuleSpec("R248", "FTP Upload To External Host", SeverityLevel.High) { AnyText = new[] { "STOR", "APPE", "ftp upload" }, Ports = new[] { 20, 21 }, RequireExternalDestination = true },
                ["R249"] = new ExpansionRuleSpec("R249", "SMB Upload To External Host", SeverityLevel.Critical) { AnyText = new[] { "smb", "write", "tree connect" }, Ports = new[] { 445, 139 }, RequireExternalDestination = true },
                ["R250"] = new ExpansionRuleSpec("R250", "Large HTTP POST To IP Literal", SeverityLevel.High) { AnyText = new[] { "POST" }, RequireExternalDestination = true, RequireHttp = true, Threshold = 10, Scope = "source-destination" },
                ["R251"] = new ExpansionRuleSpec("R251", "Multipart Upload To Unknown Domain", SeverityLevel.High) { AnyText = new[] { "multipart/form-data", "filename=" }, RequireExternalDestination = true, RequireHttp = true },
                ["R252"] = new ExpansionRuleSpec("R252", "High Entropy Outbound URI Path", SeverityLevel.Medium) { RequireExternalDestination = true, RequireHttp = true, RequireHighEntropyUri = true },
                ["R253"] = new ExpansionRuleSpec("R253", "Base64 Blob In HTTP POST", SeverityLevel.High) { AnyText = new[] { "POST", "base64", "data=" }, RequireExternalDestination = true, RequireHttp = true },
                ["R254"] = new ExpansionRuleSpec("R254", "Repeated Small Chunk Uploads", SeverityLevel.High) { AnyText = new[] { "POST", "PUT", "PATCH" }, RequireExternalDestination = true, RequireHttp = true, Threshold = 40, Scope = "source-destination" },
                ["R255"] = new ExpansionRuleSpec("R255", "Off-Hours Bulk Egress Indicator", SeverityLevel.Medium) { AnyText = new[] { "backup", "export", "archive", "sync" }, RequireExternalDestination = true, Threshold = 20, WindowSeconds = 600 },
                ["R256"] = new ExpansionRuleSpec("R256", "Internal Data Staging Server Behavior", SeverityLevel.High) { AnyText = new[] { "staging", "dump", "archive", "backup" }, RequireInternalSource = true, Threshold = 25, WindowSeconds = 600, DistinctField = "destination" },
                ["R257"] = new ExpansionRuleSpec("R257", "Exfiltration After Credential Alert Chain", SeverityLevel.Critical) { AnyText = new[] { "exfil", "upload", "credential", "token", "password" }, RequireExternalDestination = true },
                ["R258"] = new ExpansionRuleSpec("R258", "ICMP Destination Unreachable Spike", SeverityLevel.Medium) { AnyText = new[] { "destination unreachable", "icmp type 3" }, Threshold = 20, WindowSeconds = 120, Scope = "source-destination" },
                ["R259"] = new ExpansionRuleSpec("R259", "TCP Reset Storm", SeverityLevel.Medium) { AnyText = new[] { "rst", "reset" }, RequireTcp = true, Threshold = 50, WindowSeconds = 120, Scope = "source-destination" },
                ["R260"] = new ExpansionRuleSpec("R260", "Rare TCP Option Fingerprint", SeverityLevel.Medium) { AnyText = new[] { "rare tcp option", "tcp option", "ja4t" }, RequireTcp = true },
                ["R261"] = new ExpansionRuleSpec("R261", "TTL Anomaly To Same Service", SeverityLevel.Low) { AnyText = new[] { "ttl anomaly", "ttl change", "ttl=1", "ttl 1" }, Threshold = 10, WindowSeconds = 120, Scope = "source-destination" },
                ["R262"] = new ExpansionRuleSpec("R262", "Suspicious Packet Fragmentation", SeverityLevel.High) { AnyText = new[] { "fragment", "fragmented", "ip fragment", "overlap" }, Threshold = 8, WindowSeconds = 120 },
                ["R263"] = new ExpansionRuleSpec("R263", "User-Space Proxy Process Egress", SeverityLevel.Medium) { AnyText = new[] { "proxy", "socat", "chisel", "frp", "ligolo", "cloudflared", "ngrok" }, RequireExternalDestination = true },
                ["R264"] = new ExpansionRuleSpec("R264", "Tor Directory Or Guard Connection", SeverityLevel.High) { Ports = new[] { 9001, 9030, 9050, 9150 }, HostText = new[] { "torproject", "tor", "onionoo", "directory" }, RequireExternalDestination = true },
                ["R265"] = new ExpansionRuleSpec("R265", "Public VPN Proxy Domain Contact", SeverityLevel.Medium) { HostText = new[] { "nordvpn", "expressvpn", "protonvpn", "mullvad", "surfshark", "windscribe", "hola", "hidemyass" }, RequireExternalDestination = true },
                ["R266"] = new ExpansionRuleSpec("R266", "New Process Initiating Network Egress", SeverityLevel.Low) { RequireExternalDestination = true, RequireBaselineFirstSeen = true },
                ["R267"] = new ExpansionRuleSpec("R267", "Suspicious Process Name Network Egress", SeverityLevel.High) { AnyText = new[] { "powershell", "pwsh", "cmd.exe", "wscript", "cscript", "mshta", "rundll32", "regsvr32", "certutil", "bitsadmin" }, RequireExternalDestination = true },
                ["R268"] = new ExpansionRuleSpec("R268", "DNS Or HTTP From Script Interpreter", SeverityLevel.High) { AnyText = new[] { "python", "node", "perl", "ruby", "powershell", "wscript", "cscript" }, RequireExternalDestination = true },
                ["R269"] = new ExpansionRuleSpec("R269", "Security Tool Update Block Indicator", SeverityLevel.Medium) { AnyText = new[] { "windows defender", "microsoft defender", "crowdstrike", "sentinelone", "carbon black", "update failed", "blocked" }, RequireExternalDestination = true },
                ["R270"] = new ExpansionRuleSpec("R270", "Detection Pipeline Tampering Indicator", SeverityLevel.Critical) { AnyText = new[] { "disable logging", "stop service", "kill sensor", "tamper", "etw disabled", "audit disabled" } },
                ["R271"] = new ExpansionRuleSpec("R271", "Threat Feed IOC With Low Reputation Overlap", SeverityLevel.Critical) { AnyText = new[] { "ioc", "threat feed", "malicious", "reputation" }, RequireExternalDestination = true },
                ["R272"] = new ExpansionRuleSpec("R272", "Multi-Signal Rule Stack Surge From Host", SeverityLevel.High) { AnyText = new[] { "R0", "rule", "alert", "detection" }, Threshold = 10 },
                ["R273"] = new ExpansionRuleSpec("R273", "Impossible Travel Authentication Sequence", SeverityLevel.High) { AnyText = new[] { "login", "impossible travel", "geo velocity", "new country" }, Threshold = 2, WindowSeconds = 600, DistinctField = "country" },
                ["R274"] = new ExpansionRuleSpec("R274", "MFA Push Fatigue Pattern", SeverityLevel.High) { AnyText = new[] { "mfa push", "push denied", "mfa denied", "number matching", "approve sign-in" }, Threshold = 5, Scope = "source-destination" },
                ["R275"] = new ExpansionRuleSpec("R275", "OAuth Device Code Phishing Indicator", SeverityLevel.High) { AnyText = new[] { "device_code", "user_code", "device login", "/devicecode", "verification_uri" }, RequireHttp = true },
                ["R276"] = new ExpansionRuleSpec("R276", "OAuth Consent Grant Abuse Indicator", SeverityLevel.High) { AnyText = new[] { "admin_consent", "consent", "offline_access", "mail.read", "files.read.all", "application permission" }, RequireHttp = true },
                ["R277"] = new ExpansionRuleSpec("R277", "Legacy Protocol Authentication Attempt", SeverityLevel.Medium) { AnyText = new[] { "basic auth", "imap auth", "pop3 auth", "smtp auth", "legacy auth" }, Ports = new[] { 110, 143, 993, 995, 587, 25 } },
                ["R278"] = new ExpansionRuleSpec("R278", "Password Spray Low And Slow Across Accounts", SeverityLevel.High) { AnyText = new[] { "invalid password", "failed login", "bad credentials", "authentication failed" }, Threshold = 12, WindowSeconds = 900, DistinctField = "host" },
                ["R279"] = new ExpansionRuleSpec("R279", "Credential Stuffing Rotating User Agent", SeverityLevel.High) { AnyText = new[] { "login", "signin", "password", "credential" }, RequireHttp = true, Threshold = 12, DistinctField = "uri", Scope = "source-destination" },
                ["R280"] = new ExpansionRuleSpec("R280", "Session Token Replay Across Geographies", SeverityLevel.High) { AnyText = new[] { "session replay", "reused token", "refresh token", "access token", "cookie replay" }, Threshold = 3, WindowSeconds = 900, DistinctField = "country" },
                ["R281"] = new ExpansionRuleSpec("R281", "Suspicious Admin Console Login To Cloud", SeverityLevel.High) { AnyText = new[] { "console.aws.amazon.com", "portal.azure.com", "console.cloud.google.com", "admin.google.com", "login.microsoftonline.com" }, RequireExternalDestination = true, RequireHttp = true },
                ["R282"] = new ExpansionRuleSpec("R282", "VPN Login Followed By Internal Scan", SeverityLevel.Critical) { AnyText = new[] { "vpn", "login", "scan", "sweep", "rdp", "smb" }, Threshold = 8, WindowSeconds = 600 },
                ["R283"] = new ExpansionRuleSpec("R283", "SAML RelayState Injection Pattern", SeverityLevel.High) { AnyText = new[] { "relaystate=", "samlresponse", "samlrequest", "redirect_uri=http", "relaystate=http" }, RequireHttp = true },
                ["R284"] = new ExpansionRuleSpec("R284", "OIDC Authorization Code Leakage In URL", SeverityLevel.High) { AnyText = new[] { "code=", "id_token=", "access_token=", "openid", "oauth2/authorize" }, RequireHttp = true },
                ["R285"] = new ExpansionRuleSpec("R285", "SCIM Bulk User Enumeration", SeverityLevel.Medium) { AnyText = new[] { "/scim/", "/Users", "/Groups", "filter=userName", "startIndex" }, RequireHttp = true, Threshold = 20, Scope = "source-destination" },
                ["R286"] = new ExpansionRuleSpec("R286", "LDAP Simple Bind Over Cleartext External", SeverityLevel.High) { AnyText = new[] { "simple bind", "ldap bind", "bindrequest" }, Ports = new[] { 389 }, RequireExternalDestination = true },
                ["R287"] = new ExpansionRuleSpec("R287", "Kerberos Preauth Failure Distributed Spray", SeverityLevel.High) { AnyText = new[] { "preauth failed", "krb5kdc_err_preauth_failed", "kerberos failure" }, Ports = new[] { 88 }, Threshold = 15, Scope = "source-destination" },
                ["R288"] = new ExpansionRuleSpec("R288", "NTLMv1 Authentication Observed", SeverityLevel.High) { AnyText = new[] { "ntlmv1", "lanman", "lm response", "ntlm version 1" } },
                ["R289"] = new ExpansionRuleSpec("R289", "RADIUS Authentication Failure Burst", SeverityLevel.Medium) { AnyText = new[] { "radius", "access-reject", "authentication reject" }, Ports = new[] { 1812, 1813, 1645, 1646 }, Threshold = 10, Scope = "source-destination" },
                ["R290"] = new ExpansionRuleSpec("R290", "Citrix Gateway Exploit Probe", SeverityLevel.High) { AnyText = new[] { "/vpn/", "/vpns/", "citrix", "netscaler", "ns_af", "ns_gui", "citrixbleed" }, RequireHttp = true },
                ["R291"] = new ExpansionRuleSpec("R291", "Fortinet SSL VPN Exploit Probe", SeverityLevel.High) { AnyText = new[] { "/remote/", "fortinet", "fortigate", "sslvpn", "forticlient", "/remote/login" }, RequireHttp = true },
                ["R292"] = new ExpansionRuleSpec("R292", "Palo Alto GlobalProtect Exploit Probe", SeverityLevel.High) { AnyText = new[] { "globalprotect", "/global-protect/", "/ssl-vpn/", "prelogin.esp", "panos" }, RequireHttp = true },
                ["R293"] = new ExpansionRuleSpec("R293", "Kubernetes Anonymous API Discovery Probe", SeverityLevel.High) { AnyText = new[] { "/api/v1", "/apis/", "kubernetes", "api discovery" }, Ports = new[] { 6443, 8443, 443 }, RequireHttp = true },
                ["R294"] = new ExpansionRuleSpec("R294", "Kubernetes Secrets API Access Probe", SeverityLevel.Critical) { AnyText = new[] { "/secrets", "api/v1/secrets", "secret?", "kind=Secret" }, RequireHttp = true },
                ["R295"] = new ExpansionRuleSpec("R295", "Kubernetes Exec Into Pod Over API", SeverityLevel.Critical) { AnyText = new[] { "/exec", "pods/exec", "command=", "container=" }, RequireHttp = true },
                ["R296"] = new ExpansionRuleSpec("R296", "Kubernetes PortForward Abuse Indicator", SeverityLevel.High) { AnyText = new[] { "/portforward", "pods/portforward", "portforward" }, RequireHttp = true },
                ["R297"] = new ExpansionRuleSpec("R297", "Kubernetes ServiceAccount Token Exfil", SeverityLevel.Critical) { AnyText = new[] { "serviceaccount", "token", "/var/run/secrets/kubernetes.io", "bearer ey" }, RequireHttp = true },
                ["R298"] = new ExpansionRuleSpec("R298", "Container Runtime Socket Exposure Probe", SeverityLevel.Critical) { AnyText = new[] { "docker.sock", "containerd.sock", "cri.sock", "/var/run/docker.sock" }, RequireHttp = true },
                ["R299"] = new ExpansionRuleSpec("R299", "Docker Remote API Container Create", SeverityLevel.Critical) { AnyText = new[] { "/containers/create", "/containers/json", "docker api", "hostconfig" }, Ports = new[] { 2375, 2376 }, RequireHttp = true },
                ["R300"] = new ExpansionRuleSpec("R300", "Kubernetes Etcd Client Access External", SeverityLevel.Critical) { AnyText = new[] { "etcd", "/v3/kv/range", "/v3/auth", "client cert" }, Ports = new[] { 2379, 2380 }, RequireExternalDestination = true },
                ["R301"] = new ExpansionRuleSpec("R301", "Kubelet Readonly Port Probe", SeverityLevel.High) { AnyText = new[] { "/pods", "/metrics", "/runningpods", "kubelet" }, Ports = new[] { 10250, 10255 }, RequireHttp = true },
                ["R302"] = new ExpansionRuleSpec("R302", "Kubelet Run Or Exec Probe", SeverityLevel.Critical) { AnyText = new[] { "/run/", "/exec/", "/attach/", "kubelet" }, Ports = new[] { 10250, 10255 }, RequireHttp = true },
                ["R303"] = new ExpansionRuleSpec("R303", "Container Registry Manifest Enumeration", SeverityLevel.Medium) { AnyText = new[] { "/v2/", "/manifests/", "docker-distribution-api-version", "manifest" }, RequireHttp = true, Threshold = 20, Scope = "source-destination" },
                ["R304"] = new ExpansionRuleSpec("R304", "Container Registry Anonymous Pull Burst", SeverityLevel.Medium) { AnyText = new[] { "/v2/", "/blobs/", "pull", "registry" }, RequireHttp = true, Threshold = 40, WindowSeconds = 600, Scope = "source-destination" },
                ["R305"] = new ExpansionRuleSpec("R305", "Image Registry Push From Workstation", SeverityLevel.High) { AnyText = new[] { "PUT", "PATCH", "/v2/", "/blobs/uploads", "manifest" }, RequireExternalDestination = true, RequireHttp = true },
                ["R306"] = new ExpansionRuleSpec("R306", "Docker Build Context Archive Upload", SeverityLevel.High) { AnyText = new[] { "build context", "dockerfile", "context.tar", "/build" }, RequireExternalDestination = true, RequireHttp = true },
                ["R307"] = new ExpansionRuleSpec("R307", "Kubernetes Dashboard Exposure Probe", SeverityLevel.High) { AnyText = new[] { "kubernetes-dashboard", "/api/v1/login", "dashboard", "csrf" }, RequireHttp = true },
                ["R308"] = new ExpansionRuleSpec("R308", "Helm Tiller Legacy Port Exposure", SeverityLevel.High) { AnyText = new[] { "tiller", "helm", "release list" }, Ports = new[] { 44134 } },
                ["R309"] = new ExpansionRuleSpec("R309", "Istio Envoy Admin Endpoint Probe", SeverityLevel.High) { AnyText = new[] { "/stats", "/clusters", "/config_dump", "envoy admin" }, Ports = new[] { 15000, 15090 }, RequireHttp = true },
                ["R310"] = new ExpansionRuleSpec("R310", "Service Mesh Sidecar Bypass Pattern", SeverityLevel.Medium) { AnyText = new[] { "istio", "linkerd", "sidecar bypass", "x-envoy-original-path", "mesh bypass" }, RequireHttp = true },
                ["R311"] = new ExpansionRuleSpec("R311", "Cloud Workload Metadata Token Request", SeverityLevel.Critical) { AnyText = new[] { "metadata", "identity/oauth2/token", "iam/security-credentials", "169.254.169.254" }, RequireHttp = true },
                ["R312"] = new ExpansionRuleSpec("R312", "Kubernetes Network Policy Bypass Indicator", SeverityLevel.High) { AnyText = new[] { "networkpolicy", "bypass", "hostnetwork", "privileged pod", "egress unrestricted" }, RequireHttp = true },
                ["R313"] = new ExpansionRuleSpec("R313", "Direct SMTP To MX From Workstation", SeverityLevel.High) { AnyText = new[] { "smtp", "mail from", "rcpt to" }, Ports = new[] { 25, 465, 587 }, RequireExternalDestination = true },
                ["R314"] = new ExpansionRuleSpec("R314", "SMTP Authentication Failure Burst", SeverityLevel.Medium) { AnyText = new[] { "smtp auth failed", "535 authentication", "invalid login" }, Ports = new[] { 25, 465, 587 }, Threshold = 10, Scope = "source-destination" },
                ["R315"] = new ExpansionRuleSpec("R315", "IMAP Login Failure Spray", SeverityLevel.Medium) { AnyText = new[] { "imap", "login failed", "authentication failed" }, Ports = new[] { 143, 993 }, Threshold = 10, Scope = "source-destination" },
                ["R316"] = new ExpansionRuleSpec("R316", "POP3 Cleartext Credential Exposure", SeverityLevel.High) { AnyText = new[] { "USER ", "PASS ", "pop3 login" }, Ports = new[] { 110 } },
                ["R317"] = new ExpansionRuleSpec("R317", "Exchange Autodiscover External Spray", SeverityLevel.Medium) { AnyText = new[] { "autodiscover", "/autodiscover/autodiscover.xml", "legacydn" }, RequireHttp = true, Threshold = 12, Scope = "source-destination" },
                ["R318"] = new ExpansionRuleSpec("R318", "EWS Enumeration Burst", SeverityLevel.Medium) { AnyText = new[] { "/ews/", "exchange.asmx", "finditem", "resolveNames" }, RequireHttp = true, Threshold = 15, Scope = "source-destination" },
                ["R319"] = new ExpansionRuleSpec("R319", "OWA Admin Or ECP Probe", SeverityLevel.High) { AnyText = new[] { "/owa/", "/ecp/", "exchange control panel", "owa/auth" }, RequireHttp = true },
                ["R320"] = new ExpansionRuleSpec("R320", "M365 Graph Mail Export Pattern", SeverityLevel.High) { AnyText = new[] { "graph.microsoft.com", "/messages", "/mailFolders", "delta", "export" }, RequireExternalDestination = true, RequireHttp = true },
                ["R321"] = new ExpansionRuleSpec("R321", "Gmail API Bulk Message Read", SeverityLevel.High) { AnyText = new[] { "gmail.googleapis.com", "/gmail/v1/users", "messages", "threads" }, RequireExternalDestination = true, RequireHttp = true, Threshold = 20 },
                ["R322"] = new ExpansionRuleSpec("R322", "Mail Forwarding Rule Creation Indicator", SeverityLevel.High) { AnyText = new[] { "inbox rule", "forwardingSmtpAddress", "forwardTo", "redirectTo", "new-inboxrule" }, RequireHttp = true },
                ["R323"] = new ExpansionRuleSpec("R323", "Suspicious Attachment Download Burst", SeverityLevel.Medium) { AnyText = new[] { "attachment", "download", "contentBytes", "mime" }, RequireHttp = true, Threshold = 25, Scope = "source-destination" },
                ["R324"] = new ExpansionRuleSpec("R324", "Phishing Kit URI Pattern", SeverityLevel.High) { AnyText = new[] { "/login.php", "/verify.php", "/webmail/", "/office365/", "/microsoft/verify", "/dropbox/login" }, RequireHttp = true },
                ["R325"] = new ExpansionRuleSpec("R325", "Lookalike Sender Domain Contact", SeverityLevel.Medium) { AnyText = new[] { "xn--", "secure-login", "account-verify", "microsoftonline-login", "goog1e" }, RequireHttp = true },
                ["R326"] = new ExpansionRuleSpec("R326", "DMARC SPF DKIM Recon Query Burst", SeverityLevel.Low) { AnyText = new[] { "_dmarc", "_spf", "domainkey", "dkim" }, RequireDns = true, Threshold = 15 },
                ["R327"] = new ExpansionRuleSpec("R327", "Slack OAuth App Install Callback", SeverityLevel.Medium) { AnyText = new[] { "slack.com/oauth", "oauth.v2.access", "slack app", "client_secret" }, RequireHttp = true },
                ["R328"] = new ExpansionRuleSpec("R328", "Teams Webhook Abuse Indicator", SeverityLevel.High) { AnyText = new[] { "webhook.office.com", "office.com/webhook", "teams webhook", "IncomingWebhook" }, RequireExternalDestination = true, RequireHttp = true },
                ["R329"] = new ExpansionRuleSpec("R329", "SharePoint Bulk Download Pattern", SeverityLevel.High) { AnyText = new[] { "sharepoint.com", "/_api/web/GetFileByServerRelativeUrl", "download.aspx" }, RequireExternalDestination = true, RequireHttp = true, Threshold = 30, WindowSeconds = 600 },
                ["R330"] = new ExpansionRuleSpec("R330", "OneDrive Anonymous Share Link Mass Access", SeverityLevel.Medium) { AnyText = new[] { "1drv.ms", "onedrive.live.com", "download?resid", "authkey=" }, RequireExternalDestination = true, RequireHttp = true, Threshold = 20, WindowSeconds = 600 },
                ["R331"] = new ExpansionRuleSpec("R331", "Calendar Invite Phishing Link Pattern", SeverityLevel.Medium) { AnyText = new[] { "calendar invite", "ics", "meeting link", "zoom", "teams", "phishing" }, RequireHttp = true },
                ["R332"] = new ExpansionRuleSpec("R332", "Email Archive Export Download", SeverityLevel.High) { AnyText = new[] { "pst", "mbox", "mailbox export", "ediscovery export", "compliance search" }, RequireExternalDestination = true, RequireHttp = true },
                ["R333"] = new ExpansionRuleSpec("R333", "SMB Null Session Enumeration", SeverityLevel.High) { AnyText = new[] { "null session", "anonymous logon", "IPC$", "tree connect" }, Ports = new[] { 445, 139 } },
                ["R334"] = new ExpansionRuleSpec("R334", "SMB Named Pipe Enumeration Burst", SeverityLevel.Medium) { AnyText = new[] { "named pipe", "srvsvc", "samr", "lsarpc", "wkssvc" }, Ports = new[] { 445 }, Threshold = 12, Scope = "source-destination" },
                ["R335"] = new ExpansionRuleSpec("R335", "LSARPC SAMR Enumeration Pattern", SeverityLevel.High) { AnyText = new[] { "lsarpc", "samr", "lookupnames", "enumdomains", "querydisplayinfo" }, Ports = new[] { 445, 135 } },
                ["R336"] = new ExpansionRuleSpec("R336", "DRSUAPI Replication Attempt", SeverityLevel.Critical) { AnyText = new[] { "drsuapi", "getncchanges", "replication", "dcsync" }, Ports = new[] { 135, 445, 389 } },
                ["R337"] = new ExpansionRuleSpec("R337", "Kerberos S4U Delegation Abuse Indicator", SeverityLevel.High) { AnyText = new[] { "s4u2self", "s4u2proxy", "constrained delegation", "forwardable" }, Ports = new[] { 88 } },
                ["R338"] = new ExpansionRuleSpec("R338", "Kerberos RC4 Downgrade Indicator", SeverityLevel.Medium) { AnyText = new[] { "rc4-hmac", "etype 23", "kerberos rc4", "downgrade" }, Ports = new[] { 88 } },
                ["R339"] = new ExpansionRuleSpec("R339", "SMB Signing Disabled Sensitive Host", SeverityLevel.High) { AnyText = new[] { "smb signing disabled", "signing not required", "message signing disabled" }, Ports = new[] { 445 } },
                ["R340"] = new ExpansionRuleSpec("R340", "Remote Registry Service Access", SeverityLevel.Medium) { AnyText = new[] { "remote registry", "winreg", "BaseRegOpenKey", "registry" }, Ports = new[] { 445, 135 } },
                ["R341"] = new ExpansionRuleSpec("R341", "Scheduled Task Remote Creation Pattern", SeverityLevel.High) { AnyText = new[] { "schtasks", "atsvc", "scheduled task", "task scheduler" }, Ports = new[] { 445, 135 } },
                ["R342"] = new ExpansionRuleSpec("R342", "Windows Admin Center Exposure Probe", SeverityLevel.High) { AnyText = new[] { "windows admin center", "/api/nodes", "gateway/plugin" }, Ports = new[] { 6516, 443 }, RequireHttp = true },
                ["R343"] = new ExpansionRuleSpec("R343", "PowerShell Remoting Encoded Command", SeverityLevel.High) { AnyText = new[] { "-enc", "encodedcommand", "powershell", "pwsh" }, Ports = new[] { 5985, 5986 } },
                ["R344"] = new ExpansionRuleSpec("R344", "WMI Event Subscription Remote Pattern", SeverityLevel.High) { AnyText = new[] { "wmi", "__eventfilter", "commandlineeventconsumer", "wmiprvse" }, Ports = new[] { 135, 445 } },
                ["R345"] = new ExpansionRuleSpec("R345", "DCOM MMC20 Lateral Indicator", SeverityLevel.High) { AnyText = new[] { "mmc20.application", "dcom", "executeShellCommand" }, Ports = new[] { 135 } },
                ["R346"] = new ExpansionRuleSpec("R346", "MSSQL xp_cmdshell Use Indicator", SeverityLevel.Critical) { AnyText = new[] { "xp_cmdshell", "sp_configure", "ole automation" }, Ports = new[] { 1433 } },
                ["R347"] = new ExpansionRuleSpec("R347", "MSSQL Linked Server Enumeration", SeverityLevel.Medium) { AnyText = new[] { "sp_linkedservers", "openquery", "linked server" }, Ports = new[] { 1433 } },
                ["R348"] = new ExpansionRuleSpec("R348", "LDAP AdminSDHolder Recon", SeverityLevel.Medium) { AnyText = new[] { "adminsdholder", "cn=system", "sdprop" }, Ports = new[] { 389, 636 } },
                ["R349"] = new ExpansionRuleSpec("R349", "LDAP Kerberoast SPN Enumeration", SeverityLevel.High) { AnyText = new[] { "serviceprincipalname", "spn", "kerberoast", "tgs" }, Ports = new[] { 389, 636, 88 } },
                ["R350"] = new ExpansionRuleSpec("R350", "LDAP Password Policy Recon", SeverityLevel.Low) { AnyText = new[] { "pwdpolicy", "maxPwdAge", "lockoutThreshold", "domainDNS" }, Ports = new[] { 389, 636 } },
                ["R351"] = new ExpansionRuleSpec("R351", "NTLM Authentication To External Host", SeverityLevel.High) { AnyText = new[] { "ntlm", "negotiate", "authenticate" }, Ports = new[] { 445, 80, 443 }, RequireExternalDestination = true },
                ["R352"] = new ExpansionRuleSpec("R352", "LLMNR NBNS Responder Tool Indicator", SeverityLevel.High) { AnyText = new[] { "responder", "llmnr poison", "nbns poison", "wpAD poison" }, Ports = new[] { 5355, 137 } },
                ["R353"] = new ExpansionRuleSpec("R353", "GitHub Personal Access Token In Traffic", SeverityLevel.Critical) { AnyText = new[] { "ghp_", "github_pat_", "gho_", "ghu_", "ghs_" }, RequireHttp = true },
                ["R354"] = new ExpansionRuleSpec("R354", "GitLab Private Token In Traffic", SeverityLevel.Critical) { AnyText = new[] { "private-token", "glpat-", "gitlab-token" }, RequireHttp = true },
                ["R355"] = new ExpansionRuleSpec("R355", "Jenkins Script Console Probe", SeverityLevel.High) { AnyText = new[] { "/scriptText", "/script", "jenkins", "groovy" }, RequireHttp = true },
                ["R356"] = new ExpansionRuleSpec("R356", "Jenkins Crumb Issuer Enumeration", SeverityLevel.Medium) { AnyText = new[] { "/crumbIssuer/api/json", "Jenkins-Crumb", "crumbIssuer" }, RequireHttp = true },
                ["R357"] = new ExpansionRuleSpec("R357", "TeamCity Auth Bypass Probe", SeverityLevel.High) { AnyText = new[] { "/app/rest", "teamcity", "authentication bypass", "/admin/diagnostic.jsp" }, RequireHttp = true },
                ["R358"] = new ExpansionRuleSpec("R358", "Bamboo Build Artifact Bulk Download", SeverityLevel.Medium) { AnyText = new[] { "bamboo", "artifact", "download all", "build result" }, RequireHttp = true, Threshold = 20, WindowSeconds = 600, Scope = "source-destination" },
                ["R359"] = new ExpansionRuleSpec("R359", "Azure DevOps PAT In URL", SeverityLevel.Critical) { AnyText = new[] { "dev.azure.com", "personalaccesstoken", "pat=", "_apis" }, RequireHttp = true },
                ["R360"] = new ExpansionRuleSpec("R360", "CircleCI API Token Exposure", SeverityLevel.High) { AnyText = new[] { "circle-token", "circleci.com/api", "CIRCLECI_TOKEN" }, RequireHttp = true },
                ["R361"] = new ExpansionRuleSpec("R361", "GitHub Actions OIDC Token Request", SeverityLevel.High) { AnyText = new[] { "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "oidc/token", "github actions" }, RequireHttp = true },
                ["R362"] = new ExpansionRuleSpec("R362", "GitHub Actions Runner Registration Token", SeverityLevel.High) { AnyText = new[] { "registration-token", "actions/runner-registration", "runner token" }, RequireHttp = true },
                ["R363"] = new ExpansionRuleSpec("R363", "CI Artifact Archive Download Burst", SeverityLevel.High) { AnyText = new[] { "artifact", "artifacts.zip", "build.zip", "download artifacts" }, RequireHttp = true, Threshold = 25, WindowSeconds = 600 },
                ["R364"] = new ExpansionRuleSpec("R364", "Secrets Manager API Enumeration", SeverityLevel.High) { AnyText = new[] { "secretsmanager", "listsecrets", "getsecretvalue", "secret name" }, RequireHttp = true },
                ["R365"] = new ExpansionRuleSpec("R365", "HashiCorp Vault Token In HTTP", SeverityLevel.Critical) { AnyText = new[] { "x-vault-token", "vault token", "/v1/secret", "vault" }, RequireHttp = true },
                ["R366"] = new ExpansionRuleSpec("R366", "Vault Transit Decrypt Burst", SeverityLevel.High) { AnyText = new[] { "/v1/transit/decrypt", "vault", "decrypt" }, RequireHttp = true, Threshold = 15, Scope = "source-destination" },
                ["R367"] = new ExpansionRuleSpec("R367", "Terraform Cloud Token Exposure", SeverityLevel.High) { AnyText = new[] { "app.terraform.io", "terraform-token", "TF_TOKEN", "/api/v2" }, RequireHttp = true },
                ["R368"] = new ExpansionRuleSpec("R368", "Docker Hub Pull Storm", SeverityLevel.Medium) { AnyText = new[] { "registry-1.docker.io", "auth.docker.io", "ratelimit", "docker pull" }, RequireHttp = true, Threshold = 50, WindowSeconds = 600 },
                ["R369"] = new ExpansionRuleSpec("R369", "NPM Token Exposure", SeverityLevel.Critical) { AnyText = new[] { "_authToken", "npm_token", "//registry.npmjs.org/:_authToken" }, RequireHttp = true },
                ["R370"] = new ExpansionRuleSpec("R370", "PyPI Credential Upload Attempt", SeverityLevel.High) { AnyText = new[] { "pypi", "twine", "__token__", "/legacy/" }, RequireHttp = true },
                ["R371"] = new ExpansionRuleSpec("R371", "Maven Repository Credential Use", SeverityLevel.High) { AnyText = new[] { "maven", "nexus", "artifactory", "repository", "authorization: basic" }, RequireHttp = true },
                ["R372"] = new ExpansionRuleSpec("R372", "Dependency Confusion Package Name Pattern", SeverityLevel.Medium) { AnyText = new[] { "dependency confusion", "internal package", "private package", "scoped package" }, RequireHttp = true },
                ["R373"] = new ExpansionRuleSpec("R373", "AWS STS AssumeRole Burst", SeverityLevel.High) { AnyText = new[] { "sts.amazonaws.com", "AssumeRole", "AssumeRoleWithWebIdentity" }, RequireHttp = true, Threshold = 10 },
                ["R374"] = new ExpansionRuleSpec("R374", "AWS IAM AccessKey In URL", SeverityLevel.Critical) { AnyText = new[] { "AKIA", "ASIA", "aws_access_key_id", "X-Amz-Credential" }, RequireHttp = true },
                ["R375"] = new ExpansionRuleSpec("R375", "AWS S3 ListBuckets External", SeverityLevel.Medium) { AnyText = new[] { "s3.amazonaws.com", "ListBuckets", "?list-type=2", "x-amz" }, RequireExternalDestination = true, RequireHttp = true },
                ["R376"] = new ExpansionRuleSpec("R376", "AWS S3 GetObject Bulk Download", SeverityLevel.High) { AnyText = new[] { "s3.amazonaws.com", "GetObject", "x-amz-request-id" }, RequireExternalDestination = true, RequireHttp = true, Threshold = 25, WindowSeconds = 600 },
                ["R377"] = new ExpansionRuleSpec("R377", "AWS EC2 UserData Metadata Probe", SeverityLevel.Critical) { AnyText = new[] { "latest/user-data", "latest/meta-data/user-data", "169.254.169.254" }, RequireHttp = true },
                ["R378"] = new ExpansionRuleSpec("R378", "AWS Lambda Invoke Burst", SeverityLevel.Medium) { AnyText = new[] { "lambda.amazonaws.com", "InvokeFunction", "/2015-03-31/functions" }, RequireHttp = true, Threshold = 30, WindowSeconds = 600 },
                ["R379"] = new ExpansionRuleSpec("R379", "AWS CloudTrail StopLogging Indicator", SeverityLevel.Critical) { AnyText = new[] { "StopLogging", "DeleteTrail", "cloudtrail.amazonaws.com" }, RequireHttp = true },
                ["R380"] = new ExpansionRuleSpec("R380", "AWS GuardDuty Finding Exfil Indicator", SeverityLevel.High) { AnyText = new[] { "guardduty", "finding", "export findings", "GetFindings" }, RequireHttp = true },
                ["R381"] = new ExpansionRuleSpec("R381", "Azure ARM Token Request Burst", SeverityLevel.Medium) { AnyText = new[] { "management.azure.com", "oauth2/token", "client_credentials" }, RequireHttp = true, Threshold = 20 },
                ["R382"] = new ExpansionRuleSpec("R382", "Azure KeyVault Secret Enumeration", SeverityLevel.High) { AnyText = new[] { "vault.azure.net", "/secrets", "api-version=7", "keyvault" }, RequireHttp = true },
                ["R383"] = new ExpansionRuleSpec("R383", "Azure Storage SAS Token In URL", SeverityLevel.High) { AnyText = new[] { "blob.core.windows.net", "sig=", "se=", "sp=", "sv=" }, RequireHttp = true },
                ["R384"] = new ExpansionRuleSpec("R384", "Azure IMDS Token Request", SeverityLevel.Critical) { AnyText = new[] { "metadata/identity/oauth2/token", "Metadata:true", "api-version=2018-02-01" }, RequireHttp = true },
                ["R385"] = new ExpansionRuleSpec("R385", "GCP OAuth Scope Broad Request", SeverityLevel.High) { AnyText = new[] { "metadata.google.internal", "scopes", "cloud-platform", "computeMetadata/v1" }, RequireHttp = true },
                ["R386"] = new ExpansionRuleSpec("R386", "GCP Storage SignedURL Mass Access", SeverityLevel.High) { AnyText = new[] { "storage.googleapis.com", "X-Goog-Signature", "X-Goog-Credential" }, RequireHttp = true, Threshold = 20, WindowSeconds = 600 },
                ["R387"] = new ExpansionRuleSpec("R387", "GCP ServiceAccount Key Download", SeverityLevel.Critical) { AnyText = new[] { "iam.googleapis.com", "serviceAccounts/keys", "privateKeyData" }, RequireHttp = true },
                ["R388"] = new ExpansionRuleSpec("R388", "Cloudflare Tunnel Creation Indicator", SeverityLevel.High) { AnyText = new[] { "cloudflared", "trycloudflare.com", "cloudflare tunnel", "argotunnel" }, RequireExternalDestination = true },
                ["R389"] = new ExpansionRuleSpec("R389", "Ngrok Tunnel Creation Or Auth", SeverityLevel.High) { AnyText = new[] { "ngrok", "ngrok-agent", "ngrok.com", "authtoken" }, RequireExternalDestination = true },
                ["R390"] = new ExpansionRuleSpec("R390", "Tailscale Tailnet Auth Indicator", SeverityLevel.Medium) { AnyText = new[] { "tailscale", "tailnet", "login.tailscale.com", "tailscale.com" }, RequireExternalDestination = true },
                ["R391"] = new ExpansionRuleSpec("R391", "ZeroTier Network Join Indicator", SeverityLevel.Medium) { AnyText = new[] { "zerotier", "my.zerotier.com", "join network" }, RequireExternalDestination = true },
                ["R392"] = new ExpansionRuleSpec("R392", "Public Cloud CLI UserAgent From Server", SeverityLevel.Medium) { AnyText = new[] { "aws-cli", "azsdk", "azure-cli", "google-cloud-sdk", "gcloud" }, RequireExternalDestination = true },
                ["R393"] = new ExpansionRuleSpec("R393", "Cobalt Strike Beacon URI Pattern", SeverityLevel.Critical) { AnyText = new[] { "/jquery-3.3.1.min.js", "/pixel.gif", "/submit.php", "cobalt strike", "beacon" }, RequireHttp = true },
                ["R394"] = new ExpansionRuleSpec("R394", "Cobalt Strike Malleable C2 Header Pattern", SeverityLevel.Critical) { AnyText = new[] { "metadata", "__cfduid", "malware ja3", "cobalt", "beacon" }, RequireHttp = true },
                ["R395"] = new ExpansionRuleSpec("R395", "Sliver C2 MTLS Pattern", SeverityLevel.Critical) { AnyText = new[] { "sliver", "mtls", "implant", "session" }, RequireExternalDestination = true },
                ["R396"] = new ExpansionRuleSpec("R396", "Mythic Agent Callback Pattern", SeverityLevel.High) { AnyText = new[] { "mythic", "apollo", "agent callback", "tasking" }, RequireExternalDestination = true },
                ["R397"] = new ExpansionRuleSpec("R397", "Metasploit Meterpreter Stager Pattern", SeverityLevel.Critical) { AnyText = new[] { "meterpreter", "metasploit", "/MZ", "stage", "reverse_tcp" }, RequireExternalDestination = true },
                ["R398"] = new ExpansionRuleSpec("R398", "Havoc C2 Callback Pattern", SeverityLevel.Critical) { AnyText = new[] { "havoc", "demon", "teamserver", "callback" }, RequireExternalDestination = true },
                ["R399"] = new ExpansionRuleSpec("R399", "Brute Ratel Badger Pattern", SeverityLevel.Critical) { AnyText = new[] { "bruteratel", "badger", "brc4", "badger_x64" }, RequireExternalDestination = true },
                ["R400"] = new ExpansionRuleSpec("R400", "Covenant Grunt Callback Pattern", SeverityLevel.High) { AnyText = new[] { "covenant", "grunt", "launcher", "implant" }, RequireExternalDestination = true },
                ["R401"] = new ExpansionRuleSpec("R401", "Empire Stager URI Pattern", SeverityLevel.High) { AnyText = new[] { "/admin/get.php", "/news.php", "powershell empire", "stager" }, RequireHttp = true },
                ["R402"] = new ExpansionRuleSpec("R402", "AsyncRAT Telegram C2 Pattern", SeverityLevel.High) { AnyText = new[] { "telegram", "bot", "asyncrat", "sendMessage" }, RequireExternalDestination = true },
                ["R403"] = new ExpansionRuleSpec("R403", "Remcos RAT C2 Pattern", SeverityLevel.High) { AnyText = new[] { "remcos", "rat", "control", "keylogger" }, RequireExternalDestination = true },
                ["R404"] = new ExpansionRuleSpec("R404", "AgentTesla SMTP Exfil Pattern", SeverityLevel.High) { AnyText = new[] { "agenttesla", "smtp", "credentials", "mail from" }, Ports = new[] { 25, 465, 587 }, RequireExternalDestination = true },
                ["R405"] = new ExpansionRuleSpec("R405", "QakBot URI Pattern", SeverityLevel.High) { AnyText = new[] { "qakbot", "qbot", "/datacollectionservice", "/teorema505" }, RequireHttp = true },
                ["R406"] = new ExpansionRuleSpec("R406", "Emotet Loader URI Pattern", SeverityLevel.High) { AnyText = new[] { "emotet", "epoch", "/wp-content/", "/wp-admin/" }, RequireHttp = true },
                ["R407"] = new ExpansionRuleSpec("R407", "Bumblebee Loader URI Pattern", SeverityLevel.High) { AnyText = new[] { "bumblebee", "loader", "/gate.php", "/download.php" }, RequireHttp = true },
                ["R408"] = new ExpansionRuleSpec("R408", "SocGholish FakeUpdate Pattern", SeverityLevel.High) { AnyText = new[] { "fakeupdate", "update.js", "socgholish", "browser update" }, RequireHttp = true },
                ["R409"] = new ExpansionRuleSpec("R409", "Raspberry Robin Short LNK Pattern", SeverityLevel.Medium) { AnyText = new[] { "raspberry robin", ".lnk", "msiexec", "short url" }, RequireHttp = true },
                ["R410"] = new ExpansionRuleSpec("R410", "Redline Stealer Exfil Pattern", SeverityLevel.High) { AnyText = new[] { "redline", "stealer", "passwords", "wallets", "grabber" }, RequireExternalDestination = true },
                ["R411"] = new ExpansionRuleSpec("R411", "Lumma Stealer Gate Pattern", SeverityLevel.High) { AnyText = new[] { "lumma", "stealer", "gate", "loader" }, RequireExternalDestination = true },
                ["R412"] = new ExpansionRuleSpec("R412", "Generic Beacon Jitter Low Variance", SeverityLevel.Medium) { AnyText = new[] { "beacon", "jitter", "interval", "callback" }, Threshold = 6, WindowSeconds = 900, Scope = "source-destination" },
                ["R413"] = new ExpansionRuleSpec("R413", "Citrix Netscaler Gateway Scan Pattern", SeverityLevel.High) { AnyText = new[] { "netscaler", "citrix gateway", "/vpn/index.html", "/vpns/cfg/smb.conf" }, RequireHttp = true },
                ["R414"] = new ExpansionRuleSpec("R414", "Ivanti Connect Secure Exploit Probe", SeverityLevel.High) { AnyText = new[] { "ivanti", "pulse secure", "dana-na", "/api/v1/totp/user-backup-code" }, RequireHttp = true },
                ["R415"] = new ExpansionRuleSpec("R415", "F5 BIG-IP TMUI Probe", SeverityLevel.High) { AnyText = new[] { "/tmui/", "big-ip", "f5", "iControl" }, RequireHttp = true },
                ["R416"] = new ExpansionRuleSpec("R416", "SonicWall SSLVPN Exploit Probe", SeverityLevel.High) { AnyText = new[] { "sonicwall", "ssl-vpn", "/cgi-bin/", "auth.html" }, RequireHttp = true },
                ["R417"] = new ExpansionRuleSpec("R417", "Cisco ASA WebVPN Probe", SeverityLevel.High) { AnyText = new[] { "webvpn", "+CSCOE+", "/+CSCOE+/", "cisco asa" }, RequireHttp = true },
                ["R418"] = new ExpansionRuleSpec("R418", "MikroTik Winbox External Access", SeverityLevel.High) { AnyText = new[] { "winbox", "mikrotik", "routeros" }, Ports = new[] { 8291 }, RequireExternalDestination = true },
                ["R419"] = new ExpansionRuleSpec("R419", "Ubiquiti Discovery External Exposure", SeverityLevel.Medium) { AnyText = new[] { "ubiquiti", "unifi", "discovery" }, Ports = new[] { 10001, 8080, 8443 }, RequireExternalDestination = true },
                ["R420"] = new ExpansionRuleSpec("R420", "QNAP QTS Admin Probe", SeverityLevel.High) { AnyText = new[] { "qnap", "/cgi-bin/", "qts", "authLogin.cgi" }, RequireHttp = true },
                ["R421"] = new ExpansionRuleSpec("R421", "Synology DSM Admin Probe", SeverityLevel.High) { AnyText = new[] { "synology", "/webman/", "dsm", "SYNO.API" }, RequireHttp = true },
                ["R422"] = new ExpansionRuleSpec("R422", "VMware vCenter SOAP Probe", SeverityLevel.High) { AnyText = new[] { "/sdk", "vimService", "vcenter", "vmware" }, RequireHttp = true },
                ["R423"] = new ExpansionRuleSpec("R423", "VMware ESXi Hostd Probe", SeverityLevel.High) { AnyText = new[] { "/host", "/ui/", "hostd", "esxi" }, RequireHttp = true },
                ["R424"] = new ExpansionRuleSpec("R424", "Proxmox API Exposure Probe", SeverityLevel.High) { AnyText = new[] { "/api2/json", "proxmox", "pve", "ticket" }, RequireHttp = true },
                ["R425"] = new ExpansionRuleSpec("R425", "Apache Solr Admin Probe", SeverityLevel.High) { AnyText = new[] { "/solr/admin", "solr", "select?q=", "configsets" }, RequireHttp = true },
                ["R426"] = new ExpansionRuleSpec("R426", "Elasticsearch Cluster Info External", SeverityLevel.High) { AnyText = new[] { "/_cluster/health", "/_cat/indices", "elasticsearch" }, RequireExternalDestination = true, RequireHttp = true },
                ["R427"] = new ExpansionRuleSpec("R427", "Kibana Console Exposure", SeverityLevel.High) { AnyText = new[] { "/app/dev_tools", "kibana", "/api/console/proxy" }, RequireHttp = true },
                ["R428"] = new ExpansionRuleSpec("R428", "Grafana Admin Login Probe", SeverityLevel.Medium) { AnyText = new[] { "grafana", "/login", "/api/admin", "admin:admin" }, RequireHttp = true },
                ["R429"] = new ExpansionRuleSpec("R429", "Prometheus Metrics Exposure External", SeverityLevel.Medium) { AnyText = new[] { "/metrics", "prometheus", "go_gc_duration_seconds", "process_cpu_seconds" }, RequireExternalDestination = true, RequireHttp = true },
                ["R430"] = new ExpansionRuleSpec("R430", "Jupyter Notebook Token Probe", SeverityLevel.High) { AnyText = new[] { "jupyter", "/tree?token=", "/api/sessions", "notebook" }, RequireHttp = true },
                ["R431"] = new ExpansionRuleSpec("R431", "Airflow Admin Endpoint Probe", SeverityLevel.High) { AnyText = new[] { "airflow", "/admin/", "dag_runs", "/api/v1/dags" }, RequireHttp = true },
                ["R432"] = new ExpansionRuleSpec("R432", "Consul Nomad Admin Probe", SeverityLevel.High) { AnyText = new[] { "consul", "nomad", "/v1/agent", "/v1/catalog", "/ui/" }, RequireHttp = true },
                ["R433"] = new ExpansionRuleSpec("R433", "PostgreSQL External Login Attempt", SeverityLevel.High) { AnyText = new[] { "postgres", "authentication failed", "startup message" }, Ports = new[] { 5432 }, RequireExternalDestination = true },
                ["R434"] = new ExpansionRuleSpec("R434", "MySQL External Login Attempt", SeverityLevel.High) { AnyText = new[] { "mysql", "access denied", "handshake" }, Ports = new[] { 3306 }, RequireExternalDestination = true },
                ["R435"] = new ExpansionRuleSpec("R435", "MSSQL External Login Attempt", SeverityLevel.High) { AnyText = new[] { "mssql", "login failed", "prelogin" }, Ports = new[] { 1433 }, RequireExternalDestination = true },
                ["R436"] = new ExpansionRuleSpec("R436", "MongoDB External Exposure Probe", SeverityLevel.High) { AnyText = new[] { "mongodb", "ismaster", "hello", "saslStart" }, Ports = new[] { 27017 }, RequireExternalDestination = true },
                ["R437"] = new ExpansionRuleSpec("R437", "Redis CONFIG SET Indicator", SeverityLevel.Critical) { AnyText = new[] { "CONFIG SET", "SLAVEOF", "REPLICAOF", "redis" }, Ports = new[] { 6379 } },
                ["R438"] = new ExpansionRuleSpec("R438", "Redis Replication Abuse Indicator", SeverityLevel.Critical) { AnyText = new[] { "SLAVEOF", "REPLICAOF", "PSYNC", "FULLRESYNC" }, Ports = new[] { 6379 } },
                ["R439"] = new ExpansionRuleSpec("R439", "Memcached Stats Enumeration", SeverityLevel.Medium) { AnyText = new[] { "stats", "version", "memcached" }, Ports = new[] { 11211 } },
                ["R440"] = new ExpansionRuleSpec("R440", "Elasticsearch Snapshot Repository Probe", SeverityLevel.High) { AnyText = new[] { "/_snapshot", "repository", "_cat/snapshots" }, RequireHttp = true },
                ["R441"] = new ExpansionRuleSpec("R441", "Cassandra CQL External Probe", SeverityLevel.High) { AnyText = new[] { "cassandra", "cql", "startup" }, Ports = new[] { 9042 }, RequireExternalDestination = true },
                ["R442"] = new ExpansionRuleSpec("R442", "Oracle TNS Enumeration", SeverityLevel.High) { AnyText = new[] { "oracle", "tns", "connect packet", "listener" }, Ports = new[] { 1521 } },
                ["R443"] = new ExpansionRuleSpec("R443", "CouchDB Admin Probe", SeverityLevel.High) { AnyText = new[] { "/_utils", "/_all_dbs", "couchdb" }, RequireHttp = true },
                ["R444"] = new ExpansionRuleSpec("R444", "InfluxDB Query Endpoint Exposure", SeverityLevel.High) { AnyText = new[] { "/query", "/api/v2/query", "influxdb", "flux" }, RequireHttp = true },
                ["R445"] = new ExpansionRuleSpec("R445", "ClickHouse HTTP SQL Probe", SeverityLevel.High) { AnyText = new[] { "clickhouse", "select%20", "query=select" }, RequireHttp = true },
                ["R446"] = new ExpansionRuleSpec("R446", "Neo4j Browser Exposure Probe", SeverityLevel.High) { AnyText = new[] { "neo4j", "/browser/", "cypher", "dbms" }, RequireHttp = true },
                ["R447"] = new ExpansionRuleSpec("R447", "RabbitMQ Management Probe", SeverityLevel.High) { AnyText = new[] { "rabbitmq", "/api/overview", "guest:guest" }, RequireHttp = true },
                ["R448"] = new ExpansionRuleSpec("R448", "Kafka Broker External Access", SeverityLevel.High) { AnyText = new[] { "kafka", "metadata request", "api key" }, Ports = new[] { 9092, 9093 }, RequireExternalDestination = true },
                ["R449"] = new ExpansionRuleSpec("R449", "Zookeeper Four Letter Word Probe", SeverityLevel.Medium) { AnyText = new[] { "ruok", "mntr", "stat", "conf", "zookeeper" }, Ports = new[] { 2181 } },
                ["R450"] = new ExpansionRuleSpec("R450", "NATS Broker External Access", SeverityLevel.High) { AnyText = new[] { "nats", "connect {", "pub ", "sub " }, Ports = new[] { 4222 }, RequireExternalDestination = true },
                ["R451"] = new ExpansionRuleSpec("R451", "MQTT Anonymous Login Pattern", SeverityLevel.High) { AnyText = new[] { "mqtt", "anonymous", "username=", "password=" }, Ports = new[] { 1883, 8883 } },
                ["R452"] = new ExpansionRuleSpec("R452", "Database Large Result Export Pattern", SeverityLevel.High) { AnyText = new[] { "COPY TO", "SELECT *", "export", "dump" }, Ports = new[] { 5432, 3306, 1433, 1521 }, Threshold = 10, Scope = "source-destination" },
                ["R453"] = new ExpansionRuleSpec("R453", "mDNS Service Enumeration High Rate", SeverityLevel.Medium) { AnyText = new[] { "_services._dns-sd._udp.local", "mdns", "bonjour" }, Ports = new[] { 5353 }, Threshold = 20, WindowSeconds = 120 },
                ["R454"] = new ExpansionRuleSpec("R454", "SSDP MSEARCH External Answer", SeverityLevel.Medium) { AnyText = new[] { "M-SEARCH", "ssdp:discover", "upnp" }, Ports = new[] { 1900 }, RequireExternalDestination = true },
                ["R455"] = new ExpansionRuleSpec("R455", "AirPlay Discovery From Non Media Host", SeverityLevel.Low) { AnyText = new[] { "_airplay", "_raop", "airplay" }, Ports = new[] { 5353 } },
                ["R456"] = new ExpansionRuleSpec("R456", "Chromecast Discovery Burst", SeverityLevel.Low) { AnyText = new[] { "_googlecast", "chromecast", "castv2" }, Ports = new[] { 5353, 8008, 8009 }, Threshold = 15, WindowSeconds = 120 },
                ["R457"] = new ExpansionRuleSpec("R457", "Printer JetDirect External Access", SeverityLevel.Medium) { AnyText = new[] { "jetdirect", "printer", "pjl" }, Ports = new[] { 9100 }, RequireExternalDestination = true },
                ["R458"] = new ExpansionRuleSpec("R458", "IPP Printing From External Host", SeverityLevel.Medium) { AnyText = new[] { "ipp", "/printers/", "cups" }, Ports = new[] { 631 }, RequireExternalDestination = true },
                ["R459"] = new ExpansionRuleSpec("R459", "SMB Browse Election Anomaly", SeverityLevel.Low) { AnyText = new[] { "browser election", "master browser", "netbios" }, Ports = new[] { 137, 138, 139 } },
                ["R460"] = new ExpansionRuleSpec("R460", "NetBIOS Name Query Sweep", SeverityLevel.Medium) { AnyText = new[] { "nbns", "name query", "netbios" }, Ports = new[] { 137 }, Threshold = 25, WindowSeconds = 120 },
                ["R461"] = new ExpansionRuleSpec("R461", "DHCP Starvation Candidate", SeverityLevel.High) { AnyText = new[] { "dhcp discover", "dhcp request", "starvation" }, Ports = new[] { 67, 68 }, Threshold = 40, WindowSeconds = 120 },
                ["R462"] = new ExpansionRuleSpec("R462", "DHCP Rogue Offer Detected", SeverityLevel.High) { AnyText = new[] { "dhcp offer", "rogue dhcp", "server identifier" }, Ports = new[] { 67, 68 } },
                ["R463"] = new ExpansionRuleSpec("R463", "ARP Gratuitous Storm", SeverityLevel.Medium) { AnyText = new[] { "gratuitous arp", "arp announcement" }, Threshold = 30, WindowSeconds = 120 },
                ["R464"] = new ExpansionRuleSpec("R464", "ARP Duplicate MAC FlipFlop", SeverityLevel.High) { AnyText = new[] { "duplicate mac", "mac flip", "arp conflict", "duplicate address" }, Threshold = 5, WindowSeconds = 120 },
                ["R465"] = new ExpansionRuleSpec("R465", "IPv6 SLAAC Prefix Change", SeverityLevel.Medium) { AnyText = new[] { "router advertisement", "prefix information", "slaac", "prefix change" }, Protocols = new[] { "ipv6", "icmpv6" } },
                ["R466"] = new ExpansionRuleSpec("R466", "WiFi Controller Admin Probe", SeverityLevel.High) { AnyText = new[] { "wlc", "wireless controller", "unifi", "capwap", "/manage" }, RequireHttp = true },
                ["R467"] = new ExpansionRuleSpec("R467", "CAPWAP External Controller Attempt", SeverityLevel.High) { AnyText = new[] { "capwap", "join request", "discovery request" }, Ports = new[] { 5246, 5247 }, RequireExternalDestination = true },
                ["R468"] = new ExpansionRuleSpec("R468", "Bluetooth Gateway Internet Egress", SeverityLevel.Medium) { AnyText = new[] { "bluetooth", "ble gateway", "gatt", "hci" }, RequireExternalDestination = true },
                ["R469"] = new ExpansionRuleSpec("R469", "Android Debug Bridge Network Access", SeverityLevel.High) { AnyText = new[] { "adb", "android debug bridge", "CNXN" }, Ports = new[] { 5555 } },
                ["R470"] = new ExpansionRuleSpec("R470", "Mobile MDM Enrollment Burst", SeverityLevel.Medium) { AnyText = new[] { "mdm enrollment", "device enrollment", "intune", "jamf" }, RequireHttp = true, Threshold = 15, WindowSeconds = 600 },
                ["R471"] = new ExpansionRuleSpec("R471", "RDP Clipboard File Transfer Indicator", SeverityLevel.Medium) { AnyText = new[] { "rdpdr", "cliprdr", "clipboard", "file transfer" }, Ports = new[] { 3389 } },
                ["R472"] = new ExpansionRuleSpec("R472", "Remote Support Tool Unexpected Use", SeverityLevel.Medium) { AnyText = new[] { "anydesk", "teamviewer", "screenconnect", "connectwise", "splashtop", "dwservice" }, RequireExternalDestination = true },
                ["R473"] = new ExpansionRuleSpec("R473", "Modbus Function43 DeviceId Enumeration", SeverityLevel.Medium) { AnyText = new[] { "function 43", "read device identification", "modbus" }, Ports = new[] { 502 } },
                ["R474"] = new ExpansionRuleSpec("R474", "Modbus Force Listen Only Mode Attempt", SeverityLevel.Critical) { AnyText = new[] { "force listen only", "diagnostics function 4", "modbus diagnostics" }, Ports = new[] { 502 } },
                ["R475"] = new ExpansionRuleSpec("R475", "Modbus Diagnostics Function Abuse", SeverityLevel.High) { AnyText = new[] { "diagnostics", "function 8", "clear counters", "restart communication" }, Ports = new[] { 502 } },
                ["R476"] = new ExpansionRuleSpec("R476", "Modbus Coil Write Burst", SeverityLevel.Critical) { AnyText = new[] { "write coil", "force coil", "function 5", "function 15" }, Ports = new[] { 502 }, Threshold = 5, WindowSeconds = 120, Scope = "source-destination" },
                ["R477"] = new ExpansionRuleSpec("R477", "S7 Start Stop CPU Command Indicator", SeverityLevel.Critical) { AnyText = new[] { "s7", "stop cpu", "start cpu", "plc stop" }, Ports = new[] { 102 } },
                ["R478"] = new ExpansionRuleSpec("R478", "S7 Upload Download Block Transfer", SeverityLevel.Critical) { AnyText = new[] { "s7", "upload block", "download block", "block transfer" }, Ports = new[] { 102 } },
                ["R479"] = new ExpansionRuleSpec("R479", "S7 PLC Identification Probe", SeverityLevel.Medium) { AnyText = new[] { "s7", "szl", "read szl", "plc identification" }, Ports = new[] { 102 } },
                ["R480"] = new ExpansionRuleSpec("R480", "DNP3 Control Relay Output Block", SeverityLevel.Critical) { AnyText = new[] { "dnp3", "control relay output block", "crob", "operate" }, Ports = new[] { 20000 } },
                ["R481"] = new ExpansionRuleSpec("R481", "DNP3 Freeze Counter Command", SeverityLevel.High) { AnyText = new[] { "dnp3", "freeze counter", "counter freeze" }, Ports = new[] { 20000 } },
                ["R482"] = new ExpansionRuleSpec("R482", "IEC104 Control Command External", SeverityLevel.Critical) { AnyText = new[] { "iec104", "c_sc_na_1", "c_dc_na_1", "select and execute" }, Ports = new[] { 2404 }, RequireExternalDestination = true },
                ["R483"] = new ExpansionRuleSpec("R483", "OPC UA Browse Node Burst", SeverityLevel.Medium) { AnyText = new[] { "opc ua", "browse request", "browse nodes" }, Ports = new[] { 4840 }, Threshold = 20, Scope = "source-destination" },
                ["R484"] = new ExpansionRuleSpec("R484", "OPC UA Write Request Indicator", SeverityLevel.Critical) { AnyText = new[] { "opc ua", "write request", "writevalue" }, Ports = new[] { 4840 } },
                ["R485"] = new ExpansionRuleSpec("R485", "BACnet WriteProperty Request", SeverityLevel.Critical) { AnyText = new[] { "writeproperty", "write property", "bacnet" }, Ports = new[] { 47808 } },
                ["R486"] = new ExpansionRuleSpec("R486", "BACnet DeviceCommunicationControl", SeverityLevel.Critical) { AnyText = new[] { "devicecommunicationcontrol", "disable communication", "bacnet" }, Ports = new[] { 47808 } },
                ["R487"] = new ExpansionRuleSpec("R487", "Profinet DCP Set Name Request", SeverityLevel.High) { AnyText = new[] { "profinet", "dcp set", "set name", "name of station" } },
                ["R488"] = new ExpansionRuleSpec("R488", "EtherNetIP ListIdentity Burst", SeverityLevel.Medium) { AnyText = new[] { "listidentity", "ethernet/ip", "cip" }, Ports = new[] { 44818 }, Threshold = 10, WindowSeconds = 120 },
                ["R489"] = new ExpansionRuleSpec("R489", "EtherNetIP ForwardOpen External", SeverityLevel.Critical) { AnyText = new[] { "forward open", "large forward open", "cip" }, Ports = new[] { 44818 }, RequireExternalDestination = true },
                ["R490"] = new ExpansionRuleSpec("R490", "IEC61850 MMS Write Indicator", SeverityLevel.Critical) { AnyText = new[] { "mms", "iec61850", "write request", "goose" }, Ports = new[] { 102 } },
                ["R491"] = new ExpansionRuleSpec("R491", "GOOSE Multicast Outside Substation", SeverityLevel.Critical) { AnyText = new[] { "goose", "gse", "multicast" }, RequireExternalDestination = true },
                ["R492"] = new ExpansionRuleSpec("R492", "Historian Bulk Query From Workstation", SeverityLevel.High) { AnyText = new[] { "historian", "piwebapi", "osi pi", "bulk query" }, RequireHttp = true, Threshold = 20, WindowSeconds = 600 },
                ["R493"] = new ExpansionRuleSpec("R493", "Browser Password Store File Upload", SeverityLevel.Critical) { AnyText = new[] { "Login Data", "logins.json", "key4.db", "browser password", "password store" }, RequireExternalDestination = true },
                ["R494"] = new ExpansionRuleSpec("R494", "SSH Private Key Upload", SeverityLevel.Critical) { AnyText = new[] { "id_rsa", "id_ed25519", "BEGIN OPENSSH PRIVATE KEY", "ssh private key" }, RequireExternalDestination = true },
                ["R495"] = new ExpansionRuleSpec("R495", "KeePass Database Upload", SeverityLevel.Critical) { AnyText = new[] { ".kdbx", "KeePass", "keepass database" }, RequireExternalDestination = true },
                ["R496"] = new ExpansionRuleSpec("R496", "VPN Config File Upload", SeverityLevel.High) { AnyText = new[] { ".ovpn", "wg0.conf", "wireguard", "vpn config" }, RequireExternalDestination = true },
                ["R497"] = new ExpansionRuleSpec("R497", "Browser Cookie Database Upload", SeverityLevel.Critical) { AnyText = new[] { "Cookies.sqlite", "cookies.db", "browser cookies", "session cookies" }, RequireExternalDestination = true },
                ["R498"] = new ExpansionRuleSpec("R498", "Large Clipboard Sync Upload", SeverityLevel.Medium) { AnyText = new[] { "clipboard", "clip sync", "pasteboard", "sync upload" }, RequireExternalDestination = true, Threshold = 10 },
                ["R499"] = new ExpansionRuleSpec("R499", "Remote Desktop File Transfer Burst", SeverityLevel.High) { AnyText = new[] { "rdpdr", "file transfer", "drive redirection" }, Ports = new[] { 3389 }, Threshold = 10, Scope = "source-destination" },
                ["R500"] = new ExpansionRuleSpec("R500", "Compressed Archive Then Cloud Upload", SeverityLevel.High) { AnyText = new[] { ".zip", ".7z", ".rar", "upload", "cloud" }, RequireExternalDestination = true },
                ["R501"] = new ExpansionRuleSpec("R501", "Multipart Form Data High Entropy Filename", SeverityLevel.High) { AnyText = new[] { "multipart/form-data", "filename=" }, RequireExternalDestination = true, RequireHttp = true, RequireHighEntropyUri = true },
                ["R502"] = new ExpansionRuleSpec("R502", "Data URI Base64 POST Large", SeverityLevel.High) { AnyText = new[] { "data:", "base64,", "POST" }, RequireExternalDestination = true, RequireHttp = true },
                ["R503"] = new ExpansionRuleSpec("R503", "Pastebin Raw POST Bulk", SeverityLevel.High) { AnyText = new[] { "pastebin.com", "/api/api_post.php", "paste.ee", "hastebin" }, RequireExternalDestination = true, RequireHttp = true },
                ["R504"] = new ExpansionRuleSpec("R504", "GitHub Gist Secret Post", SeverityLevel.High) { AnyText = new[] { "api.github.com/gists", "gist", "secret", "token" }, RequireExternalDestination = true, RequireHttp = true },
                ["R505"] = new ExpansionRuleSpec("R505", "Discord Attachment Upload Burst", SeverityLevel.High) { AnyText = new[] { "discord.com/api", "attachments", "multipart/form-data" }, RequireExternalDestination = true, RequireHttp = true, Threshold = 10 },
                ["R506"] = new ExpansionRuleSpec("R506", "Telegram Document Exfil Burst", SeverityLevel.High) { AnyText = new[] { "api.telegram.org", "sendDocument", "sendPhoto" }, RequireExternalDestination = true, RequireHttp = true, Threshold = 10 },
                ["R507"] = new ExpansionRuleSpec("R507", "Mega NZ Upload Pattern", SeverityLevel.High) { AnyText = new[] { "mega.nz", "mega.co.nz", "g.api.mega.co.nz", "upload" }, RequireExternalDestination = true, RequireHttp = true },
                ["R508"] = new ExpansionRuleSpec("R508", "Rclone UserAgent Egress", SeverityLevel.High) { AnyText = new[] { "rclone", "rclone/v", "User-Agent: rclone" }, RequireExternalDestination = true },
                ["R509"] = new ExpansionRuleSpec("R509", "Rsync External Push", SeverityLevel.High) { AnyText = new[] { "rsync", "rsyncd", "module list" }, Ports = new[] { 873 }, RequireExternalDestination = true },
                ["R510"] = new ExpansionRuleSpec("R510", "S3 Compatible Unknown Endpoint Upload", SeverityLevel.High) { AnyText = new[] { "x-amz-content-sha256", "s3", "PUT", "uploadId=" }, RequireExternalDestination = true, RequireHttp = true },
                ["R511"] = new ExpansionRuleSpec("R511", "DB Client Export Then HTTP Upload", SeverityLevel.Critical) { AnyText = new[] { "psql", "mysqldump", "sqlcmd", "export", "upload" }, RequireExternalDestination = true },
                ["R512"] = new ExpansionRuleSpec("R512", "Sensitive Filename To Personal Email", SeverityLevel.High) { AnyText = new[] { "gmail.com", "outlook.com", "yahoo.com", ".pem", ".kdbx", ".zip", ".sql" }, RequireExternalDestination = true, RequireHttp = true },
                ["R513"] = new ExpansionRuleSpec("R513", "SSH Dynamic SOCKS Proxy Use", SeverityLevel.High) { AnyText = new[] { "dynamic forward", "socks", "ssh -D", "direct-tcpip" }, Ports = new[] { 22 }, RequireExternalDestination = true },
                ["R514"] = new ExpansionRuleSpec("R514", "Chisel Tunnel Handshake", SeverityLevel.High) { AnyText = new[] { "chisel", "chisel-v", "reverse tunnel" }, RequireExternalDestination = true },
                ["R515"] = new ExpansionRuleSpec("R515", "FRP Tunnel Handshake", SeverityLevel.High) { AnyText = new[] { "frp", "frps", "frpc", "frp tunnel" }, RequireExternalDestination = true },
                ["R516"] = new ExpansionRuleSpec("R516", "Cloudflared Tunnel Handshake", SeverityLevel.High) { AnyText = new[] { "cloudflared", "argo tunnel", "trycloudflare", "cf tunnel" }, RequireExternalDestination = true },
                ["R517"] = new ExpansionRuleSpec("R517", "Ngrok Tunnel Handshake V2", SeverityLevel.High) { AnyText = new[] { "ngrok", "ngrok-agent", "ngrok-skip-browser-warning" }, RequireExternalDestination = true },
                ["R518"] = new ExpansionRuleSpec("R518", "Reverse SSH Tunnel Pattern", SeverityLevel.High) { AnyText = new[] { "reverse ssh", "ssh -R", "remote forward", "forwarded-tcpip" }, Ports = new[] { 22 }, RequireExternalDestination = true },
                ["R519"] = new ExpansionRuleSpec("R519", "DNS Over QUIC Unapproved Resolver", SeverityLevel.High) { AnyText = new[] { "doq", "dns over quic", "doq-i02" }, Ports = new[] { 853, 784, 8853 }, RequireExternalDestination = true, RequireUdp = true },
                ["R520"] = new ExpansionRuleSpec("R520", "MASQUE CONNECT UDP Proxy Use", SeverityLevel.Medium) { AnyText = new[] { "CONNECT-UDP", "masque", "/.well-known/masque" }, RequireExternalDestination = true, RequireHttp = true },
                ["R521"] = new ExpansionRuleSpec("R521", "HTTP CONNECT To Non Proxy Port", SeverityLevel.Medium) { AnyText = new[] { "CONNECT " }, Ports = new[] { 443, 8443, 8080, 3128, 8888 }, RequireExternalDestination = true, RequireHttp = true },
                ["R522"] = new ExpansionRuleSpec("R522", "WebSocket Tunnel To IP Literal", SeverityLevel.High) { AnyText = new[] { "Upgrade: websocket", "Sec-WebSocket-Key", "websocket" }, RequireExternalDestination = true, RequireHttp = true },
                ["R523"] = new ExpansionRuleSpec("R523", "Domain Fronting Host SNI Mismatch", SeverityLevel.High) { AnyText = new[] { "domain fronting", "host sni mismatch", "fronted" }, RequireTls = true },
                ["R524"] = new ExpansionRuleSpec("R524", "ECH To Unapproved Provider", SeverityLevel.Medium) { AnyText = new[] { "ech", "encrypted client hello", "cloudflare-ech", "grease ech" }, RequireExternalDestination = true, RequireTls = true },
                ["R525"] = new ExpansionRuleSpec("R525", "QUIC Connection ID Rotation Burst", SeverityLevel.Medium) { AnyText = new[] { "quic", "connection id rotation", "cid rotation" }, RequireExternalDestination = true, RequireUdp = true, Threshold = 20, WindowSeconds = 120, Scope = "source-destination" },
                ["R526"] = new ExpansionRuleSpec("R526", "Packet Size Mimicry Beacon", SeverityLevel.Medium) { AnyText = new[] { "packet size mimicry", "constant size", "padding", "beacon" }, Threshold = 8, WindowSeconds = 600, Scope = "source-destination" },
                ["R527"] = new ExpansionRuleSpec("R527", "Sleepy Beacon Long Gap Pattern", SeverityLevel.Medium) { AnyText = new[] { "sleepy beacon", "long gap", "beacon interval", "callback" }, Threshold = 3, WindowSeconds = 1800, Scope = "source-destination" },
                ["R528"] = new ExpansionRuleSpec("R528", "User Agent Randomization Burst", SeverityLevel.Medium) { AnyText = new[] { "user-agent", "randomized ua", "ua rotation" }, RequireHttp = true, Threshold = 15, DistinctField = "uri" },
                ["R529"] = new ExpansionRuleSpec("R529", "Sensor Heartbeat Missing For Site", SeverityLevel.High) { AnyText = new[] { "sensor heartbeat missing", "heartbeat timeout", "sensor offline" } },
                ["R530"] = new ExpansionRuleSpec("R530", "Sensor Clock Skew Increasing", SeverityLevel.Medium) { AnyText = new[] { "clock skew", "time drift", "sensor time skew" } },
                ["R531"] = new ExpansionRuleSpec("R531", "Detection Journal Disk Space Low", SeverityLevel.Critical) { AnyText = new[] { "journal disk space low", "disk full", "no space left", "journal write blocked" } },
                ["R532"] = new ExpansionRuleSpec("R532", "Outbox Retry Storm", SeverityLevel.High) { AnyText = new[] { "outbox retry", "sink retry", "delivery retry failed" }, Threshold = 5 },
                ["R533"] = new ExpansionRuleSpec("R533", "Rule Match Volume Anomaly", SeverityLevel.Medium) { AnyText = new[] { "rule volume anomaly", "match volume spike", "alert storm" }, Threshold = 10 },
                ["R534"] = new ExpansionRuleSpec("R534", "Rule Silent Unexpectedly", SeverityLevel.Medium) { AnyText = new[] { "rule silent", "no matches", "unexpected silence", "coverage gap" } },
                ["R535"] = new ExpansionRuleSpec("R535", "Telemetry Field Coverage Drop", SeverityLevel.High) { AnyText = new[] { "telemetry coverage drop", "missing field spike", "parser field missing" } },
                ["R536"] = new ExpansionRuleSpec("R536", "Parser Error Spike", SeverityLevel.High) { AnyText = new[] { "parser error", "decode error", "malformed packet", "parse failed" }, Threshold = 10 },
                ["R537"] = new ExpansionRuleSpec("R537", "GeoIP Lookup Failure Spike", SeverityLevel.Low) { AnyText = new[] { "geoip lookup failed", "geo database error", "maxmind error" }, Threshold = 10, WindowSeconds = 600 },
                ["R538"] = new ExpansionRuleSpec("R538", "Reputation Lookup Failure Spike", SeverityLevel.Low) { AnyText = new[] { "reputation lookup failed", "threat intel timeout", "abuseipdb error" }, Threshold = 10, WindowSeconds = 600 },
                ["R539"] = new ExpansionRuleSpec("R539", "Baseline Store Write Failure", SeverityLevel.High) { AnyText = new[] { "baseline write failed", "baseline store error", "baseline persistence failed" } },
                ["R540"] = new ExpansionRuleSpec("R540", "Feedback Store Write Failure", SeverityLevel.Medium) { AnyText = new[] { "feedback write failed", "feedback store error", "feedback persistence failed" } },
                ["R541"] = new ExpansionRuleSpec("R541", "Content Pack Validation Failure", SeverityLevel.Medium) { AnyText = new[] { "content pack validation failed", "invalid content pack", "pack rejected" } },
                ["R542"] = new ExpansionRuleSpec("R542", "Replay Benchmark Regression", SeverityLevel.High) { AnyText = new[] { "benchmark regression", "replay test failed", "expected match missing" } },
                ["R543"] = new ExpansionRuleSpec("R543", "Rule Config Profile Drift", SeverityLevel.Medium) { AnyText = new[] { "profile drift", "rule config drift", "unexpected profile change" } },
                ["R544"] = new ExpansionRuleSpec("R544", "Excessive Suppression Ratio", SeverityLevel.Medium) { AnyText = new[] { "suppression ratio", "too many suppressed", "suppression spike" }, Threshold = 5 },
        };

        private static readonly HashSet<int> SensitivePorts = new() { 53, 88, 135, 139, 389, 445, 464, 636, 1433, 1521, 2375, 2376, 3268, 3269, 3306, 3389, 5432, 5985, 5986, 6379, 9200, 9300, 11211, 27017 };
        private static readonly HashSet<int> ServerPorts = new() { 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 3306, 3389, 5432, 5985, 5986, 6379, 8080, 8443, 9200, 9300, 27017 };
        private static readonly HashSet<int> LateralPorts = new() { 22, 135, 139, 389, 445, 3389, 5985, 5986 };
        private static readonly HashSet<int> MqttPorts = new() { 1883, 8883 };
        private static readonly HashSet<int> CoapPorts = new() { 5683, 5684 };

        public static RuleEvaluationResult Evaluate(RuleDescriptor descriptor, RuleEvaluationContext context)
        {
            try
            {
                var evt = descriptor.RuleId switch
                {
                    "R057" => DetectNewDevice(descriptor, context),
                    "R058" => DetectNewMacVendor(descriptor, context),
                    "R059" => DetectSameMacMultipleIps(descriptor, context),
                    "R060" => DetectSameIpMultipleMacs(descriptor, context),
                    "R061" => DetectSensitiveHostExternal(descriptor, context),
                    "R062" => DetectNewInternalService(descriptor, context),
                    "R063" => DetectWorkstationActingLikeServer(descriptor, context),
                    "R064" => DetectFirstTimeDestination(descriptor, context),
                    "R065" => DetectFirstTimeAsn(descriptor, context),
                    "R066" => DetectFirstTimeCountry(descriptor, context),
                    "R067" => DetectRogueIpv6Ra(descriptor, context),
                    "R068" => DetectIpv6NdSweep(descriptor, context),
                    "R069" => DetectIpv6DuplicateOrSpoof(descriptor, context),
                    "R070" => DetectIpv6TunnelUse(descriptor, context),
                    "R071" => DetectIpv6OnIpv4OnlyNetwork(descriptor, context),
                    "R072" => DetectIpv6MulticastBurst(descriptor, context),
                    "R073" => DetectLateralSweep(descriptor, context, 3389, 4, "RDP lateral movement burst"),
                    "R074" => DetectWinRmSweep(descriptor, context),
                    "R075" => DetectWmiDcom(descriptor, context),
                    "R076" => DetectSmbAdminShare(descriptor, context),
                    "R077" => DetectRpcServiceControl(descriptor, context),
                    "R078" => DetectPsExecLike(descriptor, context),
                    "R079" => DetectLdapEnumeration(descriptor, context),
                    "R080" => DetectKerberosTgsSpike(descriptor, context),
                    "R081" => DetectAsRepRoasting(descriptor, context),
                    "R082" => DetectNtlmRelay(descriptor, context),
                    "R083" => DetectLlmnrNbnsPoisoning(descriptor, context),
                    "R084" => DetectPayloadContains(descriptor, context, SeverityLevel.Critical, "Log4Shell/JNDI lookup pattern", PayloadContainsLog4Shell),
                    "R085" => DetectPayloadContains(descriptor, context, SeverityLevel.High, "SQL injection pattern", PayloadContainsSqlInjection),
                    "R086" => DetectPayloadContains(descriptor, context, SeverityLevel.High, "path traversal/LFI pattern", PayloadContainsPathTraversal),
                    "R087" => DetectWebshellUpload(descriptor, context),
                    "R088" => DetectPayloadContains(descriptor, context, SeverityLevel.High, "suspicious serialized payload pattern", PayloadContainsSerialization),
                    "R089" => DetectPayloadContains(descriptor, context, SeverityLevel.High, "command injection pattern", PayloadContainsCommandInjection),
                    "R090" => DetectPayloadContains(descriptor, context, SeverityLevel.Critical, "reverse shell payload indicator", PayloadContainsReverseShell),
                    "R091" => DetectScannerUserAgent(descriptor, context),
                    "R092" => DetectMalwareHttpPattern(descriptor, context),
                    "R093" => DetectPayloadContains(descriptor, context, SeverityLevel.High, "PowerShell download cradle over HTTP", PayloadContainsPowerShellCradle),
                    "R094" => DetectDgaLikeDomain(descriptor, context),
                    "R095" => DetectNewHighEntropyDomain(descriptor, context),
                    "R096" => DetectFastFluxDns(descriptor, context),
                    "R097" => DetectExcessiveUniqueSubdomains(descriptor, context),
                    "R098" => DetectDynamicDnsProvider(descriptor, context),
                    "R099" => DetectNewlyRegisteredDomain(descriptor, context),
                    "R100" => DetectInternalNameToExternalResolver(descriptor, context),
                    "R101" => DetectCnameChainAbuse(descriptor, context),
                    "R102" => DetectDnsLongLabels(descriptor, context),
                    "R103" => DetectDnsBeaconingStableInterval(descriptor, context),
                    "R104" => DetectFirstTimeCloudUpload(descriptor, context),
                    "R105" => DetectLargeUploadToPersonalCloud(descriptor, context),
                    "R106" => DetectUploadAfterInternalSweep(descriptor, context),
                    "R107" => DetectSplitExfiltration(descriptor, context),
                    "R108" => DetectUploadRatio(descriptor, context),
                    "R109" => DetectHostPattern(descriptor, context, SeverityLevel.Medium, "GitHub/GitLab raw content access", IsGitRawHost),
                    "R110" => DetectHostPattern(descriptor, context, SeverityLevel.High, "chat/collaboration API egress", IsChatApiHost),
                    "R111" => DetectHostPattern(descriptor, context, SeverityLevel.High, "paste or file-drop service egress", IsPasteOrDropHost),
                    "R112" => DetectSaasExportLikePattern(descriptor, context),
                    "R113" => DetectMqttUnapprovedBroker(descriptor, context),
                    "R114" => DetectMqttTopicEnumeration(descriptor, context),
                    "R115" => DetectMqttPublishBurst(descriptor, context),
                    "R116" => DetectUpnpDiscoveryAbuse(descriptor, context),
                    "R117" => DetectTelnetLoginAttempt(descriptor, context),
                    "R118" => DetectDefaultCredentialAttempt(descriptor, context),
                    "R119" => DetectCameraNvrExternalBeacon(descriptor, context),
                    "R120" => DetectModbusOutsideApprovedSegment(descriptor, context),
                    "R121" => DetectBacnetDiscovery(descriptor, context),
                    "R122" => DetectCoapZigbeeEgress(descriptor, context),
                    _ => EvaluateExpansionRule(descriptor, context)
                };

                return evt == null
                    ? RuleEvaluationResult.NoMatch(descriptor.RuleId)
                    : RuleEvaluationResult.Match(descriptor.RuleId, evt);
            }
            catch (Exception ex)
            {
                return RuleEvaluationResult.FailedRule(descriptor.RuleId, ex);
            }
        }

        private static DetectionEvent? DetectNewDevice(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var key = NormalizeMac(r.MacSource) ?? NormalizeHost(r.Source);
            if (key == null || !IsInternal(r.Source)) return null;
            var baseline = ObserveBaseline("host", "network", key, c, $"source={r.Source}; mac={r.MacSource}");
            if (baseline.IsFirstSeen || SeenDeviceKeys.TryAdd(key, c.TimestampUtc))
                return Event(d, c, SeverityLevel.Low, $"New network device observed: {key}", $"source={r.Source}; mac={r.MacSource}; baseline={baseline.Reason}; process={r.ProcessName}");
            return null;
        }

        private static DetectionEvent? DetectNewMacVendor(RuleDescriptor d, RuleEvaluationContext c)
        {
            var mac = NormalizeMac(c.Record.MacSource);
            if (mac == null) return null;
            var oui = mac.Replace(":", string.Empty).Replace("-", string.Empty);
            if (oui.Length < 6) return null;
            var vendor = oui.Substring(0, 6).ToUpperInvariant();
            if (SeenMacVendors.TryAdd(vendor, c.TimestampUtc))
                return Event(d, c, SeverityLevel.Low, $"New MAC vendor/OUI observed: {vendor}", $"mac={mac}; source={c.Record.Source}");
            return null;
        }

        private static DetectionEvent? DetectSameMacMultipleIps(RuleDescriptor d, RuleEvaluationContext c)
        {
            var mac = NormalizeMac(c.Record.MacSource);
            var ip = NormalizeHost(c.Record.Source);
            if (mac == null || ip == null) return null;
            var ips = AddDistinct(MacToIps, mac, ip, c.TimestampUtc, LongWindow);
            if (ips >= 2)
                return Event(d, c, SeverityLevel.Medium, $"Same MAC address using multiple IPs: {mac} ({ips} IPs)", $"mac={mac}; latestIp={ip}");
            return null;
        }

        private static DetectionEvent? DetectSameIpMultipleMacs(RuleDescriptor d, RuleEvaluationContext c)
        {
            var mac = NormalizeMac(c.Record.MacSource);
            var ip = NormalizeHost(c.Record.Source);
            if (mac == null || ip == null) return null;
            var macs = AddDistinct(IpToMacs, ip, mac, c.TimestampUtc, LongWindow);
            if (macs >= 2)
                return Event(d, c, SeverityLevel.High, $"Same IP observed with multiple MAC addresses: {ip} ({macs} MACs)", $"ip={ip}; latestMac={mac}");
            return null;
        }

        private static DetectionEvent? DetectSensitiveHostExternal(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsInternal(r.Source) || !IsExternal(r.Destination)) return null;
            var sensitive = (r.SourcePort.HasValue && SensitivePorts.Contains(r.SourcePort.Value)) ||
                            (r.DestinationPort.HasValue && SensitivePorts.Contains(r.DestinationPort.Value)) ||
                            ContainsAny(Text(r), "domain controller", "ldap", "kerberos", "sql server", "postgres", "mysql", "redis", "mongodb", "elasticsearch");
            if (!sensitive) return null;
            return Event(d, c, SeverityLevel.High, "Sensitive service/host communicating externally", $"src={r.Source}; dst={r.Destination}; dstPort={r.DestinationPort}; evidence={Short(Text(r))}");
        }

        private static DetectionEvent? DetectNewInternalService(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsInternal(r.Destination) || !r.DestinationPort.HasValue || !ServerPorts.Contains(r.DestinationPort.Value)) return null;
            var ports = InternalHostServices.GetOrAdd(r.Destination!, _ => new ConcurrentDictionary<int, DateTime>());
            if (ports.TryAdd(r.DestinationPort.Value, c.TimestampUtc) && ports.Count > 1)
                return Event(d, c, SeverityLevel.Medium, $"New service observed on internal host {r.Destination}:{r.DestinationPort}", $"src={r.Source}; protocol={r.Protocol}; app={r.ApplicationProtocol}/{r.ApplicationService}");
            return null;
        }

        private static DetectionEvent? DetectWorkstationActingLikeServer(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsInternal(r.Destination) || !r.DestinationPort.HasValue || !ServerPorts.Contains(r.DestinationPort.Value)) return null;
            if (LooksLikeKnownServer(r.Destination, r.ProcessName, Text(r))) return null;
            var key = $"R063:{r.Destination}:{r.DestinationPort}";
            var srcs = AddDistinct(PerKeyDistinct, key, r.Source ?? "unknown", c.TimestampUtc, DefaultWindow);
            if (srcs >= 5)
                return Event(d, c, SeverityLevel.Medium, $"Workstation-like host receiving server traffic from {srcs} sources", $"dst={r.Destination}:{r.DestinationPort}");
            return null;
        }

        private static DetectionEvent? DetectFirstTimeDestination(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsInternal(r.Source) || string.IsNullOrWhiteSpace(r.Destination) || IsInternal(r.Destination)) return null;
            var map = SrcToDestinations.GetOrAdd(r.Source!, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            var hadBaseline = map.Count >= 8;
            var first = map.TryAdd(r.Destination!, c.TimestampUtc);
            var baseline = ObserveBaseline("host_destination", r.Source!, r.Destination!, c, $"port={r.DestinationPort}; host={BestHost(r)}");
            if ((first && hadBaseline) || (baseline.IsFirstSeen && hadBaseline))
                return Event(d, c, SeverityLevel.Low, $"First-time external destination for host {r.Source}: {r.Destination}", $"port={r.DestinationPort}; host={BestHost(r)}; baseline={baseline.Reason}");
            return null;
        }

        private static DetectionEvent? DetectFirstTimeAsn(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var asn = FirstNonEmpty(r.WhoisASN);
            if (!IsInternal(r.Source) || string.IsNullOrWhiteSpace(asn) || IsInternal(r.Destination)) return null;
            var map = SrcToAsns.GetOrAdd(r.Source!, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            var hadBaseline = map.Count >= 3;
            var first = map.TryAdd(asn!, c.TimestampUtc);
            if (first && hadBaseline)
                return Event(d, c, SeverityLevel.Low, $"First-time ASN for host {r.Source}: {asn}", $"dst={r.Destination}; org={r.WhoisOrganization}");
            return null;
        }

        private static DetectionEvent? DetectFirstTimeCountry(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var country = FirstNonEmpty(r.DstCountryIso2, r.WhoisCountry);
            if (!IsInternal(r.Source) || string.IsNullOrWhiteSpace(country) || IsInternal(r.Destination)) return null;
            var map = SrcToCountries.GetOrAdd(r.Source!, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            var hadBaseline = map.Count >= 3;
            var first = map.TryAdd(country!, c.TimestampUtc);
            if (first && hadBaseline)
                return Event(d, c, SeverityLevel.Low, $"First-time destination country for host {r.Source}: {country}", $"dst={r.Destination}; country={country}");
            return null;
        }

        private static DetectionEvent? DetectRogueIpv6Ra(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var info = Text(r);
            var icmpType = r.IcmpTypeCode.HasValue ? r.IcmpTypeCode.Value >> 8 : -1;
            if (r.IpVersion == 6 && (icmpType == 134 || ContainsAny(info, "router advertisement", "icmpv6 type 134")))
                return Event(d, c, SeverityLevel.High, "IPv6 Router Advertisement observed", $"src={r.Source}; mac={r.MacSource}; info={Short(info)}");
            return null;
        }

        private static DetectionEvent? DetectIpv6NdSweep(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var info = Text(r);
            var icmpType = r.IcmpTypeCode.HasValue ? r.IcmpTypeCode.Value >> 8 : -1;
            if (r.IpVersion != 6 && !ContainsAny(info, "neighbor solicitation", "icmpv6 type 135")) return null;
            if (icmpType != 135 && !ContainsAny(info, "neighbor solicitation", "icmpv6 type 135")) return null;
            var key = $"R068:{r.Source}";
            var threshold = Threshold(d, 15);
            var window = TimeSpan.FromSeconds(WindowSeconds(d, (int)DefaultWindow.TotalSeconds));
            var count = AddDistinct(PerKeyDistinct, key, r.Destination ?? ExtractIpv6Target(info) ?? "unknown", c.TimestampUtc, window);
            if (count >= threshold)
                return Event(d, c, SeverityLevel.Medium, $"IPv6 Neighbor Discovery sweep from {r.Source} ({count} targets)", $"info={Short(info)}");
            return null;
        }

        private static DetectionEvent? DetectIpv6DuplicateOrSpoof(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var info = Text(r);
            if (r.IpVersion == 6 && ContainsAny(info, "duplicate address", "dad failed", "spoof", "address conflict"))
                return Event(d, c, SeverityLevel.High, "IPv6 duplicate address or spoofing indicator", Short(info));
            if (r.IpVersion == 6)
                return DetectSameIpMultipleMacs(d, c);
            return null;
        }

        private static DetectionEvent? DetectIpv6TunnelUse(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r).ToLowerInvariant();
            if (r.DestinationPort == 3544 || r.SourcePort == 3544 || text.Contains("teredo") || text.Contains("isatap") || text.Contains("6to4") || StartsWithAny(r.Source, "2002:", "2001:0:") || StartsWithAny(r.Destination, "2002:", "2001:0:"))
                return Event(d, c, SeverityLevel.Medium, "IPv6 transition/tunnel protocol observed", $"src={r.Source}; dst={r.Destination}; port={r.DestinationPort}; info={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectIpv6OnIpv4OnlyNetwork(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            if (r.IpVersion == 6 && ContainsAny(text, "ipv4-only", "ipv4 only", "ipv6 disabled", "no ipv6"))
                return Event(d, c, SeverityLevel.Medium, "IPv6 traffic observed on an IPv4-only segment", Short(text));
            return null;
        }

        private static DetectionEvent? DetectIpv6MulticastBurst(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (r.IpVersion != 6 && !StartsWithAny(r.Destination, "ff02:", "ff05:")) return null;
            if (!StartsWithAny(r.Destination, "ff02:", "ff05:") && !ContainsAny(Text(r), "multicast", "mld", "ff02")) return null;
            var count = AddTime($"R072:{r.Source}", c.TimestampUtc, TimeSpan.FromSeconds(60));
            if (count >= 20)
                return Event(d, c, SeverityLevel.Medium, $"Suspicious IPv6 multicast discovery burst from {r.Source} ({count}/60s)", $"dst={r.Destination}; info={Short(Text(r))}");
            return null;
        }

        private static DetectionEvent? DetectLateralSweep(RuleDescriptor d, RuleEvaluationContext c, int port, int threshold, string summary)
        {
            var r = c.Record;
            if (!IsInternal(r.Source) || !IsInternal(r.Destination) || r.DestinationPort != port) return null;
            var effectiveThreshold = Threshold(d, threshold);
            var window = TimeSpan.FromSeconds(WindowSeconds(d, (int)DefaultWindow.TotalSeconds));
            var key = $"{d.RuleId}:{r.Source}:{port}";
            var count = AddDistinct(PerKeyDistinct, key, r.Destination ?? "unknown", c.TimestampUtc, window);
            if (count >= effectiveThreshold)
            {
                RecentInternalSweepBySource.AddOrUpdate(r.Source!, c.TimestampUtc, (_, __) => c.TimestampUtc);
                return Event(d, c, SeverityLevel.High, $"{summary} from {r.Source} ({count} internal targets)", $"port={port}; latestTarget={r.Destination}");
            }
            return null;
        }

        private static DetectionEvent? DetectWinRmSweep(RuleDescriptor d, RuleEvaluationContext c)
        {
            var p = c.Record.DestinationPort;
            if (p != 5985 && p != 5986 && !ContainsAny(Text(c.Record), "winrm", "powershell remoting")) return null;
            return DetectLateralSweep(d, c, p ?? 5985, 4, "WinRM/PowerShell remoting sweep");
        }

        private static DetectionEvent? DetectWmiDcom(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsInternal(r.Source) || !IsInternal(r.Destination)) return null;
            var text = Text(r);
            var isWmi = r.DestinationPort == 135 || (r.DestinationPort >= 49152 && r.DestinationPort <= 65535 && ContainsAny(text, "wmi", "dcom", "wmic")) || ContainsAny(text, "wmi", "dcom", "wmic");
            if (!isWmi) return null;
            var count = AddDistinct(PerKeyDistinct, $"R075:{r.Source}", r.Destination ?? "unknown", c.TimestampUtc, DefaultWindow);
            if (count >= 3 || ContainsAny(text, "wmic", "wmi", "dcom"))
                return Event(d, c, SeverityLevel.High, $"WMI/DCOM lateral movement indicator from {r.Source}", $"targets={count}; dst={r.Destination}; info={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectSmbAdminShare(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (r.DestinationPort != 445 || !IsInternal(r.Source) || !IsInternal(r.Destination)) return null;
            var text = Text(r);
            var adminShare = ContainsAny(text, "admin$", "c$", "ipc$", "\\\\admin$", "\\\\c$", "tree connect");
            var count = AddDistinct(PerKeyDistinct, $"R076:{r.Source}", r.Destination ?? "unknown", c.TimestampUtc, DefaultWindow);
            if (adminShare || count >= 5)
                return Event(d, c, SeverityLevel.High, $"SMB admin-share access pattern from {r.Source}", $"targets={count}; dst={r.Destination}; info={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectRpcServiceControl(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            if (!IsInternal(r.Source) || !IsInternal(r.Destination)) return null;
            if ((r.DestinationPort == 135 || r.DestinationPort == 445) && ContainsAny(text, "svcctl", "scmr", "service control", "createservice", "openscmanager"))
                return Event(d, c, SeverityLevel.High, "RPC service-control pattern observed", Short(text));
            var count = AddDistinct(PerKeyDistinct, $"R077:{r.Source}", r.Destination ?? "unknown", c.TimestampUtc, DefaultWindow);
            if ((r.DestinationPort == 135 || r.DestinationPort == 445) && count >= 6)
                return Event(d, c, SeverityLevel.Medium, $"RPC/SMB service-control sweep from {r.Source} ({count} targets)", $"port={r.DestinationPort}");
            return null;
        }

        private static DetectionEvent? DetectPsExecLike(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            if (r.DestinationPort == 445 && IsInternal(r.Source) && IsInternal(r.Destination) && ContainsAny(text, "psexec", "psexesvc", "admin$", "svcctl", "remcom", "paexec"))
                return Event(d, c, SeverityLevel.Critical, "PsExec-like SMB/service-control behavior", Short(text));
            return null;
        }

        private static DetectionEvent? DetectLdapEnumeration(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            if (!IsInternal(r.Source) || !(r.DestinationPort is 389 or 636 or 3268 or 3269)) return null;
            var suspicious = ContainsAny(text, "objectclass", "samaccountname", "memberof", "ldap search", "subtree", "admincount");
            var windowSeconds = WindowSeconds(d, 60);
            var threshold = Threshold(d, 40);
            var count = AddTime($"R079:{r.Source}:{r.Destination}", c.TimestampUtc, TimeSpan.FromSeconds(windowSeconds));
            if (suspicious || count >= threshold)
                return Event(d, c, SeverityLevel.Medium, $"LDAP enumeration spike from {r.Source}", $"count={count}/{windowSeconds}s; threshold={threshold}; info={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectKerberosTgsSpike(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            if (!IsInternal(r.Source) || r.DestinationPort != 88) return null;
            var isTgs = ContainsAny(text, "tgs-req", "tgs request", "kerberos tgs", "sname");
            var windowSeconds = WindowSeconds(d, 60);
            var threshold = Threshold(d, 60);
            var count = AddTime($"R080:{r.Source}", c.TimestampUtc, TimeSpan.FromSeconds(windowSeconds));
            if (isTgs || count >= threshold)
                return Event(d, c, SeverityLevel.High, $"Kerberos TGS request spike from {r.Source}", $"count={count}/{windowSeconds}s; threshold={threshold}; info={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectAsRepRoasting(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            if (!IsInternal(r.Source) || r.DestinationPort != 88) return null;
            if (ContainsAny(text, "as-req", "asrep", "as-rep", "preauth not required", "do not require preauth", "etype 23"))
                return Event(d, c, SeverityLevel.High, "AS-REP roasting heuristic", Short(text));
            return null;
        }

        private static DetectionEvent? DetectNtlmRelay(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            if (ContainsAny(text, "ntlmssp", "ntlm challenge", "ntlm negotiate", "ntlm authenticate", "relay"))
                return Event(d, c, SeverityLevel.High, "NTLM relay suspicion", Short(text));
            var isRelayPort = r.DestinationPort is 80 or 445 or 135 or 139 or 5985;
            if (isRelayPort && IsInternal(r.Source) && IsInternal(r.Destination))
            {
                var count = AddDistinct(PerKeyDistinct, $"R082:{r.Source}", r.Destination ?? "unknown", c.TimestampUtc, DefaultWindow);
                if (count >= 8) return Event(d, c, SeverityLevel.Medium, $"NTLM relay-like fan-out from {r.Source}", $"targets={count}; port={r.DestinationPort}");
            }
            return null;
        }

        private static DetectionEvent? DetectLlmnrNbnsPoisoning(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            var isNameService = r.SourcePort is 137 or 5355 || r.DestinationPort is 137 or 5355 || ContainsAny(text, "llmnr", "nbns", "netbios name");
            if (!isNameService) return null;
            if (r.DnsIsResponse || ContainsAny(text, "response", "poison", "spoof", "answered"))
                return Event(d, c, SeverityLevel.High, "LLMNR/NBNS poisoning attempt indicator", Short(text));
            return null;
        }

        private static DetectionEvent? DetectPayloadContains(RuleDescriptor d, RuleEvaluationContext c, SeverityLevel severity, string finding, Func<string, bool> predicate)
        {
            var payload = PayloadNormalizer.FromTrafficRecord(c.Record);
            var text = string.Join(" ", payload.Original, payload.Normalized, payload.LowerInvariant);
            if (string.IsNullOrWhiteSpace(text) || !predicate(text)) return null;
            var evt = Event(d, c, severity, finding, $"normalized={Short(payload.Normalized)}; original={Short(payload.Original)}");
            evt.StructuredEvidence = new DetectionEvidenceSet(new[]
            {
                new DetectionEvidenceItem("finding", finding, "rule"),
                new DetectionEvidenceItem("normalized_payload", Short(payload.Normalized), "payload-normalizer", true),
                new DetectionEvidenceItem("original_payload", Short(payload.Original), "traffic-record", true)
            }, finding);
            ConfidenceForPayload(evt, d.RuleId, payload);
            return evt;
        }

        private static DetectionEvent? DetectWebshellUpload(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var payload = PayloadNormalizer.FromTrafficRecord(r);
            var text = payload.Normalized + " " + payload.Original;
            var method = (r.HttpMethod ?? string.Empty).ToUpperInvariant();
            if (method is not ("POST" or "PUT" or "PATCH")) return null;
            if (ContainsAny(text, ".php", ".jsp", ".jspx", ".asp", ".aspx", ".ashx", ".war", "filename=", "multipart/form-data") && ContainsAny(text, "upload", "shell", "cmd", "eval", "system("))
                return Event(d, c, SeverityLevel.Critical, "Webshell upload pattern", Short(text));
            return null;
        }

        private static DetectionEvent? DetectScannerUserAgent(RuleDescriptor d, RuleEvaluationContext c)
        {
            var ua = c.Record.HttpUserAgent ?? string.Empty;
            if (ContainsAny(ua, "nmap", "masscan", "zgrab", "zmap", "nikto", "sqlmap", "dirbuster", "gobuster", "ffuf", "wpscan"))
                return Event(d, c, SeverityLevel.Medium, "Scanner user-agent observed", ua);
            return null;
        }

        private static DetectionEvent? DetectMalwareHttpPattern(RuleDescriptor d, RuleEvaluationContext c)
        {
            // Evaluate the observed HTTP request target, not Info, hostnames,
            // process names, authorization headers or descriptive replay notes.
            var r = c.Record;
            if (string.IsNullOrWhiteSpace(r.HttpUri)
                || (string.IsNullOrWhiteSpace(r.HttpMethod)
                    && !string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)))
                return null;

            var uri = r.HttpUri!;
            // Only explicit, path-delimited malware/C2 endpoint indicators.
            // Generic words such as "rat", "beacon" and "malware" in commentary
            // are not proof of a malicious HTTP request.
            if (Regex.IsMatch(uri, @"(?:^|[/?#])(?:gate\.php|cnc|bot|panel)(?:[/?#]|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                return Event(d, c, SeverityLevel.Critical, "Known malware/C2 HTTP URI pattern", Short(uri));
            return null;
        }

        private static DetectionEvent? DetectDgaLikeDomain(RuleDescriptor d, RuleEvaluationContext c)
        {
            var q = DomainFromRecord(c.Record);
            if (q == null || !IsDns(c.Record)) return null;
            var sld = SecondLevelLabel(q);
            if (sld.Length >= 12 && ShannonEntropy(sld) >= 3.2 && VowelRatio(sld) < 0.35)
                return Event(d, c, SeverityLevel.High, $"DGA-like DNS query: {q}", $"sld={sld}; entropy={ShannonEntropy(sld):F2}");
            return null;
        }

        private static DetectionEvent? DetectNewHighEntropyDomain(RuleDescriptor d, RuleEvaluationContext c)
        {
            var q = DomainFromRecord(c.Record);
            if (q == null || !IsDns(c.Record)) return null;
            var first = SeenDomains.TryAdd(q, c.TimestampUtc);
            var baseline = ObserveBaseline("dns_domain", c.Record.Source ?? "unknown", q, c, $"qtype={c.Record.DnsQtype}");
            var ent = ShannonEntropy(q.Replace(".", string.Empty));
            if ((first || baseline.IsFirstSeen) && q.Length >= 35 && ent >= 3.8)
                return Event(d, c, SeverityLevel.Medium, $"Newly observed high-entropy domain: {q}", $"entropy={ent:F2}; baseline={baseline.Reason}");
            return null;
        }

        private static DetectionEvent? DetectFastFluxDns(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsDns(r) || string.IsNullOrWhiteSpace(r.DnsAnswers)) return null;
            var ipCount = Regex.Matches(r.DnsAnswers, @"\b(?:\d{1,3}\.){3}\d{1,3}\b").Count;
            var lowTtl = r.DnsTtl.HasValue && r.DnsTtl.Value > 0 && r.DnsTtl.Value <= 120;
            if (ipCount >= 4 && lowTtl)
                return Event(d, c, SeverityLevel.High, $"Fast-flux DNS pattern for {DomainFromRecord(r) ?? "unknown"}", $"answers={ipCount}; ttl={r.DnsTtl}");
            return null;
        }

        private static DetectionEvent? DetectExcessiveUniqueSubdomains(RuleDescriptor d, RuleEvaluationContext c)
        {
            var q = DomainFromRecord(c.Record);
            if (q == null || !IsDns(c.Record)) return null;
            var root = RootDomain(q);
            var left = q.EndsWith(root, StringComparison.OrdinalIgnoreCase) ? q[..Math.Max(0, q.Length - root.Length)].TrimEnd('.') : q;
            if (string.IsNullOrWhiteSpace(left)) return null;
            var count = AddDistinct(DomainSubLabels, $"R097:{c.Record.Source}:{root}", left, c.TimestampUtc, DefaultWindow);
            if (count >= 25)
                return Event(d, c, SeverityLevel.High, $"Excessive unique subdomains for {root} from {c.Record.Source}", $"uniqueSubdomains={count}; latest={q}");
            return null;
        }

        private static DetectionEvent? DetectDynamicDnsProvider(RuleDescriptor d, RuleEvaluationContext c)
        {
            var q = DomainFromRecord(c.Record) ?? BestHost(c.Record);
            if (string.IsNullOrWhiteSpace(q)) return null;
            if (ContainsAny(q, "duckdns.org", "no-ip", "ddns.net", "dynu", "hopto.org", "myqnapcloud", "synology.me", "tplinkdns", "dyndns", "afraid.org", "serveo.net"))
                return Event(d, c, SeverityLevel.Medium, $"Suspicious dynamic DNS provider used: {q}", $"dst={c.Record.Destination}");
            return null;
        }

        private static DetectionEvent? DetectNewlyRegisteredDomain(RuleDescriptor d, RuleEvaluationContext c)
        {
            var q = DomainFromRecord(c.Record) ?? BestHost(c.Record);
            var text = Text(c.Record);
            if (string.IsNullOrWhiteSpace(q)) return null;
            var enrichmentSaysNew = ContainsAny(text, "newly registered", "domain age", "registered days", "created within", "whois age") || (c.Record.ReputationLastSeen.HasValue && (c.TimestampUtc - c.Record.ReputationLastSeen.Value.ToUniversalTime()).TotalDays <= 7);
            if (enrichmentSaysNew)
                return Event(d, c, SeverityLevel.High, $"DNS/query to newly registered or newly seen domain: {q}", Short(text));
            return null;
        }

        private static DetectionEvent? DetectInternalNameToExternalResolver(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var q = DomainFromRecord(r);
            if (q == null || !IsDns(r) || !IsExternal(r.Destination)) return null;
            if (EndsWithAny(q, ".local", ".lan", ".home", ".internal", ".corp", ".intranet") || !q.Contains('.'))
                return Event(d, c, SeverityLevel.Medium, $"Internal DNS name sent to external resolver: {q}", $"resolver={r.Destination}");
            return null;
        }

        private static DetectionEvent? DetectCnameChainAbuse(RuleDescriptor d, RuleEvaluationContext c)
        {
            var answers = c.Record.DnsAnswers ?? string.Empty;
            if (!IsDns(c.Record) || string.IsNullOrWhiteSpace(answers)) return null;
            var cnameCount = Regex.Matches(answers, "CNAME", RegexOptions.IgnoreCase).Count;
            if (cnameCount >= 3 || answers.Count(ch => ch == '>') >= 3)
                return Event(d, c, SeverityLevel.Medium, "DNS CNAME chain abuse pattern", Short(answers));
            return null;
        }

        private static DetectionEvent? DetectDnsLongLabels(RuleDescriptor d, RuleEvaluationContext c)
        {
            var q = DomainFromRecord(c.Record);
            if (q == null || !IsDns(c.Record)) return null;
            var labels = q.Split('.', StringSplitOptions.RemoveEmptyEntries);
            var maxLabel = labels.Length == 0 ? 0 : labels.Max(x => x.Length);
            var ent = ShannonEntropy(q.Replace(".", string.Empty));
            var labelThreshold = Threshold(d, 50);
            var queryLengthThreshold = RuleEngine.GetRuleIntSetting(d.RuleId, "QueryLengthThreshold", 180, 40, 4096);
            var entropyThreshold = DoubleSetting(d, "EntropyThreshold", 3.5, 1.0, 8.0);
            if (maxLabel >= labelThreshold || (q.Length >= queryLengthThreshold && ent >= entropyThreshold))
                return Event(d, c, SeverityLevel.High, $"DNS tunneling long-label pattern: {q}", $"maxLabel={maxLabel}; labelThreshold={labelThreshold}; length={q.Length}; queryLengthThreshold={queryLengthThreshold}; entropy={ent:F2}; entropyThreshold={entropyThreshold:F2}");
            return null;
        }

        private static DetectionEvent? DetectDnsBeaconingStableInterval(RuleDescriptor d, RuleEvaluationContext c)
        {
            var q = DomainFromRecord(c.Record);
            if (q == null || !IsDns(c.Record)) return null;
            var key = $"R103:{c.Record.Source}:{RootDomain(q)}";
            var list = DnsIntervals.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.Add(c.TimestampUtc);
                list.RemoveAll(t => c.TimestampUtc - t > TimeSpan.FromMinutes(15));
                if (list.Count < 6) return null;
                var intervals = new List<double>();
                for (int i = 1; i < list.Count; i++) intervals.Add((list[i] - list[i - 1]).TotalSeconds);
                var avg = intervals.Average();
                if (avg < 10) return null;
                var std = Math.Sqrt(intervals.Select(x => (x - avg) * (x - avg)).Average());
                if (std <= Math.Max(1.0, avg * 0.10))
                    return Event(d, c, SeverityLevel.High, $"DNS beaconing with stable interval to {RootDomain(q)}", $"samples={list.Count}; avg={avg:F1}s; std={std:F1}s");
            }
            return null;
        }

        private static DetectionEvent? DetectFirstTimeCloudUpload(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsUploadMethod(r) || !IsCloudStorageHost(BestHost(r))) return null;
            var key = $"R104:{r.Source}";
            var count = AddDistinct(PerKeyDistinct, key, RootDomain(BestHost(r)), c.TimestampUtc, LongWindow);
            if (count == 1)
                return Event(d, c, SeverityLevel.Medium, $"First-time cloud storage upload from {r.Source}", $"host={BestHost(r)}; method={r.HttpMethod}");
            return null;
        }

        private static DetectionEvent? DetectLargeUploadToPersonalCloud(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsCloudStorageHost(BestHost(r)) || !IsInternal(r.Source) || !IsExternal(r.Destination)) return null;
            var bytes = Math.Max(r.Length, r.L4Len ?? 0);
            var total = AddBytes($"R105:{r.Source}:{RootDomain(BestHost(r))}", c.TimestampUtc, bytes, TimeSpan.FromMinutes(10));
            if (total >= 5_000_000 || bytes >= 1_000_000)
                return Event(d, c, SeverityLevel.High, $"Large upload to personal cloud provider from {r.Source}", $"host={BestHost(r)}; bytesWindow={total}; packetBytes={bytes}");
            return null;
        }

        private static DetectionEvent? DetectUploadAfterInternalSweep(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsInternal(r.Source) || !IsExternal(r.Destination) || !IsUploadLike(r)) return null;
            if (r.Source != null && RecentInternalSweepBySource.TryGetValue(r.Source, out var sweepAt) && c.TimestampUtc - sweepAt <= TimeSpan.FromMinutes(30))
                return Event(d, c, SeverityLevel.Critical, $"Upload after internal sweep from {r.Source}", $"sweepAt={sweepAt:o}; dst={r.Destination}; host={BestHost(r)}");
            return null;
        }

        private static DetectionEvent? DetectSplitExfiltration(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsInternal(r.Source) || !IsExternal(r.Destination)) return null;
            var bytes = Math.Max(r.Length, r.L4Len ?? 0);
            if (bytes <= 0) return null;
            AddBytes($"R107-bytes:{r.Source}", c.TimestampUtc, bytes, TimeSpan.FromMinutes(10));
            var dests = AddDistinct(PerKeyDistinct, $"R107-dsts:{r.Source}", r.Destination ?? "unknown", c.TimestampUtc, TimeSpan.FromMinutes(10));
            var total = SumBytes($"R107-bytes:{r.Source}", c.TimestampUtc, TimeSpan.FromMinutes(10));
            if (dests >= 8 && total >= 3_000_000)
                return Event(d, c, SeverityLevel.High, $"Possible exfiltration split across {dests} external destinations", $"src={r.Source}; bytesWindow={total}");
            return null;
        }

        private static DetectionEvent? DetectUploadRatio(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var bytes = Math.Max(r.Length, r.L4Len ?? 0);
            if (bytes <= 0 || string.IsNullOrWhiteSpace(r.Source) || string.IsNullOrWhiteSpace(r.Destination)) return null;
            if (IsInternal(r.Source) && IsExternal(r.Destination))
            {
                var state = UploadRatioByHost.AddOrUpdate(r.Source!, (bytes, 0, c.TimestampUtc), (_, old) => (old.OutBytes + bytes, old.InBytes, c.TimestampUtc));
                if (state.OutBytes >= 5_000_000 && state.InBytes > 0 && state.OutBytes / Math.Max(1.0, state.InBytes) >= 8.0)
                    return Event(d, c, SeverityLevel.High, $"Excessive upload ratio for {r.Source}", $"out={state.OutBytes}; in={state.InBytes}");
                if (state.OutBytes >= 10_000_000 && state.InBytes == 0)
                    return Event(d, c, SeverityLevel.High, $"High outbound-only volume for {r.Source}", $"out={state.OutBytes}; in=0");
            }
            else if (IsExternal(r.Source) && IsInternal(r.Destination))
            {
                UploadRatioByHost.AddOrUpdate(r.Destination!, (0, bytes, c.TimestampUtc), (_, old) => (old.OutBytes, old.InBytes + bytes, c.TimestampUtc));
            }
            return null;
        }

        private static DetectionEvent? DetectHostPattern(RuleDescriptor d, RuleEvaluationContext c, SeverityLevel severity, string summary, Func<string, bool> hostPredicate)
        {
            var host = BestHost(c.Record);
            if (string.IsNullOrWhiteSpace(host) || !IsInternal(c.Record.Source) || !IsExternal(c.Record.Destination)) return null;
            if (hostPredicate(host)) return Event(d, c, severity, summary, $"host={host}; dst={c.Record.Destination}; uri={c.Record.HttpUri}");
            return null;
        }

        private static DetectionEvent? DetectSaasExportLikePattern(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var host = BestHost(r);
            var text = Text(r);
            if (!IsInternal(r.Source) || !IsExternal(r.Destination) || string.IsNullOrWhiteSpace(host)) return null;
            if (IsSaasHost(host) && ContainsAny(text, "export", "download", "archive", "bulk", "takeout", "csv", "backup") && (IsUploadLike(r) || Math.Max(r.Length, r.L4Len ?? 0) > 500_000))
                return Event(d, c, SeverityLevel.High, "SaaS export-like traffic pattern", $"host={host}; method={r.HttpMethod}; evidence={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectMqttUnapprovedBroker(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (!IsMqtt(r)) return null;
            if (IsExternal(r.Destination) || ContainsAny(BestHost(r), "shiftr.io", "hivemq.cloud", "cloudmqtt", "emqxsl", "mqtt-dashboard"))
                return Event(d, c, SeverityLevel.High, "MQTT broker connection to unapproved/external host", $"dst={r.Destination}; host={BestHost(r)}; port={r.DestinationPort}");
            return null;
        }

        private static DetectionEvent? DetectMqttTopicEnumeration(RuleDescriptor d, RuleEvaluationContext c)
        {
            if (!IsMqtt(c.Record)) return null;
            var text = Text(c.Record);
            if (ContainsAny(text, "subscribe", "topic") && (text.Contains("/#") || text.Contains("/+") || text.Contains("#") || text.Contains("+")))
                return Event(d, c, SeverityLevel.Medium, "MQTT wildcard topic enumeration", Short(text));
            var count = AddDistinct(PerKeyDistinct, $"R114:{c.Record.Source}", ExtractTopic(text) ?? text, c.TimestampUtc, DefaultWindow);
            if (count >= 30) return Event(d, c, SeverityLevel.Medium, $"MQTT topic enumeration from {c.Record.Source}", $"uniqueTopics={count}");
            return null;
        }

        private static DetectionEvent? DetectMqttPublishBurst(RuleDescriptor d, RuleEvaluationContext c)
        {
            if (!IsMqtt(c.Record) || !ContainsAny(Text(c.Record), "publish", "pubrel", "puback")) return null;
            var windowSeconds = WindowSeconds(d, 60);
            var threshold = Threshold(d, 60);
            var count = AddTime($"R115:{c.Record.Source}", c.TimestampUtc, TimeSpan.FromSeconds(windowSeconds));
            if (count >= threshold)
                return Event(d, c, SeverityLevel.Medium, $"MQTT high-frequency publish burst from {c.Record.Source}", $"count={count}/{windowSeconds}s; threshold={threshold}");
            return null;
        }

        private static DetectionEvent? DetectUpnpDiscoveryAbuse(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            var isUpnp = r.DestinationPort == 1900 || r.SourcePort == 1900 || ContainsAny(text, "ssdp", "upnp", "m-search");
            if (!isUpnp) return null;
            var windowSeconds = WindowSeconds(d, 60);
            var threshold = Threshold(d, 20);
            var count = AddTime($"R116:{r.Source}", c.TimestampUtc, TimeSpan.FromSeconds(windowSeconds));
            if (IsExternal(r.Destination) || count >= threshold)
                return Event(d, c, SeverityLevel.Medium, $"UPnP/SSDP discovery abuse from {r.Source}", $"count={count}/{windowSeconds}s; threshold={threshold}; dst={r.Destination}; info={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectTelnetLoginAttempt(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (r.DestinationPort == 23 || r.SourcePort == 23 || ContainsAny(Text(r), "telnet", "login:", "password:"))
                return Event(d, c, SeverityLevel.High, "Telnet login attempt to IoT/network device", Short(Text(r)));
            return null;
        }

        private static DetectionEvent? DetectDefaultCredentialAttempt(RuleDescriptor d, RuleEvaluationContext c)
        {
            var text = Text(c.Record);
            if (ContainsAny(text, "admin:admin", "admin:password", "root:root", "root:admin", "user:user", "guest:guest", "ubnt:ubnt", "support:support", "default password", "factory default"))
                return Event(d, c, SeverityLevel.Critical, "Default credential attempt", Short(text));
            return null;
        }

        private static DetectionEvent? DetectCameraNvrExternalBeacon(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            var looksCamera = ContainsAny(text, "camera", "nvr", "dvr", "rtsp", "onvif", "hikvision", "dahua", "axis") || r.SourcePort is 554 or 8554 || r.DestinationPort is 554 or 8554;
            if (!looksCamera || !IsInternal(r.Source) || !IsExternal(r.Destination)) return null;
            var count = AddTime($"R119:{r.Source}:{r.Destination}", c.TimestampUtc, TimeSpan.FromMinutes(15));
            if (count >= 5 || r.DestinationPort is 554 or 8554)
                return Event(d, c, SeverityLevel.High, "Camera/NVR external beacon or stream", $"count={count}; dst={r.Destination}; info={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectModbusOutsideApprovedSegment(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            if (r.SourcePort == 502 || r.DestinationPort == 502 || ContainsAny(Text(r), "modbus"))
            {
                if (IsExternal(r.Source) || IsExternal(r.Destination) || !IsInternal(r.Source) || !IsInternal(r.Destination))
                    return Event(d, c, SeverityLevel.Critical, "Modbus traffic outside approved internal segment", $"src={r.Source}; dst={r.Destination}; port={r.DestinationPort}; info={Short(Text(r))}");
            }
            return null;
        }

        private static DetectionEvent? DetectBacnetDiscovery(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            var isBacnet = r.SourcePort == 47808 || r.DestinationPort == 47808 || ContainsAny(text, "bacnet", "who-is", "i-am");
            if (!isBacnet) return null;
            if (ContainsAny(text, "who-is", "discover", "broadcast") || IsExternal(r.Source) || IsExternal(r.Destination))
                return Event(d, c, SeverityLevel.High, "BACnet discovery from non-admin/unexpected host", $"src={r.Source}; dst={r.Destination}; info={Short(text)}");
            return null;
        }

        private static DetectionEvent? DetectCoapZigbeeEgress(RuleDescriptor d, RuleEvaluationContext c)
        {
            var r = c.Record;
            var text = Text(r);
            var isCoapZigbee = CoapPorts.Contains(r.SourcePort ?? -1) || CoapPorts.Contains(r.DestinationPort ?? -1) || ContainsAny(text, "coap", "zigbee", "zigbee2mqtt", "zcl", "gateway");
            if (isCoapZigbee && IsInternal(r.Source) && IsExternal(r.Destination))
                return Event(d, c, SeverityLevel.High, "CoAP/Zigbee gateway suspicious external egress", $"dst={r.Destination}; port={r.DestinationPort}; info={Short(text)}");
            return null;
        }


        private static DetectionEvent? EvaluateExpansionRule(RuleDescriptor descriptor, RuleEvaluationContext context)
        {
            if (!ExpansionRuleSpecs.TryGetValue(descriptor.RuleId, out var spec)) return null;

            var r = context.Record;
            var precision = RulePrecisionCatalog.Validate(descriptor.RuleId, r);
            if (!precision.CanEvaluate) return null;

            var text = Text(r);
            var host = BestHost(r);
            var protocol = FirstNonEmpty(r.ApplicationProtocol, r.ApplicationService, r.Protocol) ?? string.Empty;
            var evidence = new List<string>();
            var evidenceKinds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var matched = false;

            if (spec.RequireInternalSource)
            {
                if (!IsInternal(r.Source)) return null;
                evidenceKinds.Add("direction");
                evidence.Add("src_internal=true");
            }

            if (spec.RequireExternalDestination)
            {
                if (!IsExternal(r.Destination)) return null;
                evidenceKinds.Add("external-destination");
                evidence.Add("dst_external=true");
            }

            if (spec.RequireHttp)
            {
                if (!LooksHttp(r)) return null;
                evidenceKinds.Add("http");
                if (!string.IsNullOrWhiteSpace(r.HttpMethod) || !string.IsNullOrWhiteSpace(r.HttpUri) || !string.IsNullOrWhiteSpace(r.HttpRequestHeaders) || !string.IsNullOrWhiteSpace(r.HttpUserAgent))
                    evidenceKinds.Add("http-request");
                evidence.Add("telemetry=http");
            }

            if (spec.RequireDns)
            {
                if (string.IsNullOrWhiteSpace(r.DnsQname)) return null;
                evidenceKinds.Add("dns");
                evidence.Add($"dns_qname={Short(r.DnsQname)}");
            }

            if (spec.RequireTls)
            {
                if (string.IsNullOrWhiteSpace(r.Sni) && string.IsNullOrWhiteSpace(r.TlsVersion) && string.IsNullOrWhiteSpace(r.Ja3) && string.IsNullOrWhiteSpace(r.Ja4) && string.IsNullOrWhiteSpace(r.CertIssuer) && string.IsNullOrWhiteSpace(r.CertSubject)) return null;
                evidenceKinds.Add("tls");
                evidence.Add($"tls={FirstNonEmpty(r.TlsVersion, r.Sni, r.Ja3, r.Ja4, r.CertIssuer)}");
            }

            if (spec.RequireUdp)
            {
                if (!r.IsUdp && !ContainsAny(r.Protocol, "udp")) return null;
                evidenceKinds.Add("protocol");
                evidence.Add("transport=udp");
            }

            if (spec.RequireTcp)
            {
                if (!r.IsTcp && !ContainsAny(r.Protocol, "tcp")) return null;
                evidenceKinds.Add("protocol");
                evidence.Add("transport=tcp");
            }

            if (spec.Ports.Length > 0)
            {
                if (!spec.Ports.Contains(r.SourcePort ?? -1) && !spec.Ports.Contains(r.DestinationPort ?? -1)) return null;
                matched = true;
                evidenceKinds.Add("port");
                evidence.Add($"port={r.SourcePort}->{r.DestinationPort}");
            }

            if (spec.Protocols.Length > 0)
            {
                if (!spec.Protocols.Any(p => ContainsAny(protocol, p))) return null;
                matched = true;
                evidenceKinds.Add("protocol");
                evidence.Add($"protocol={protocol}");
            }

            if (spec.DnsQtypes.Length > 0)
            {
                if (string.IsNullOrWhiteSpace(r.DnsQtype) || !spec.DnsQtypes.Any(q => string.Equals(q, r.DnsQtype, StringComparison.OrdinalIgnoreCase))) return null;
                matched = true;
                evidenceKinds.Add("dns");
                evidence.Add($"dns_qtype={r.DnsQtype}");
            }

            if (spec.AnyText.Length > 0)
            {
                var hit = spec.AnyText.FirstOrDefault(k => ContainsAny(text, k));
                if (hit == null) return null;
                matched = true;
                evidenceKinds.Add("text");
                if (ContainsAny(r.HttpUri, hit)) evidenceKinds.Add("uri");
                else if (ContainsAny(r.HttpRequestHeaders, hit)) evidenceKinds.Add("header");
                else if (ContainsAny(r.HttpUserAgent, hit)) evidenceKinds.Add("user-agent");
                else if (ContainsAny($"{host} {r.DnsQname} {r.HttpHost} {r.Sni}", hit)) evidenceKinds.Add("host");
                else if (RulePrecisionCatalog.HasField("iot_or_ot_context", r) && ContainsAny(r.Info, hit)) evidenceKinds.Add("ot-protocol-payload");
                else if (RulePrecisionCatalog.HasField("admin_or_service_context", r) && ContainsAny(r.Info, hit)) evidenceKinds.Add("service-command");
                evidence.Add($"matched_text={hit}");
            }

            if (spec.AllText.Length > 0)
            {
                foreach (var k in spec.AllText)
                    if (!ContainsAny(text, k)) return null;
                matched = true;
                evidenceKinds.Add("text");
                evidence.Add("matched_all_text=" + string.Join(",", spec.AllText));
            }

            if (spec.HostText.Length > 0)
            {
                var hay = $"{host} {r.DnsQname} {r.HttpHost} {r.Sni}";
                var hit = spec.HostText.FirstOrDefault(k => ContainsAny(hay, k));
                if (hit == null) return null;
                matched = true;
                evidenceKinds.Add("host");
                evidence.Add($"matched_host={hit}; host={host}");
            }

            if (spec.MinimumUriLength > 0)
            {
                var uri = r.HttpUri ?? string.Empty;
                if (uri.Length < spec.MinimumUriLength) return null;
                matched = true;
                evidenceKinds.Add("uri");
                evidence.Add($"uri_length={uri.Length}");
            }

            if (spec.RequireHighEntropyHost)
            {
                var candidate = DomainFromRecord(r) ?? host;
                if (string.IsNullOrWhiteSpace(candidate)) return null;
                var label = candidate.Split('.').OrderByDescending(x => x.Length).FirstOrDefault() ?? candidate;
                var entropy = ShannonEntropy(label);
                var consonantRatio = Ratio(label, ch => "bcdfghjklmnpqrstvwxyz".Contains(char.ToLowerInvariant(ch)));
                if (entropy < 3.2 && consonantRatio < 0.72) return null;
                matched = true;
                evidenceKinds.Add("entropy");
                evidence.Add($"host_entropy={entropy:F2}; consonant_ratio={consonantRatio:F2}; host={candidate}");
            }

            if (spec.RequireHighEntropyUri)
            {
                var uri = r.HttpUri ?? string.Empty;
                if (uri.Length < 32 || ShannonEntropy(uri) < 4.0) return null;
                matched = true;
                evidenceKinds.Add("entropy");
                evidence.Add($"uri_entropy={ShannonEntropy(uri):F2}; uri_length={uri.Length}");
            }

            if (spec.RequireBaselineFirstSeen)
            {
                var subject = FirstNonEmpty(r.Source, r.ProcessName) ?? "unknown";
                var value = FirstNonEmpty(r.ProcessName, host, r.Destination, protocol) ?? "unknown";
                var baseline = ObserveBaseline("expansion_rule", $"{descriptor.RuleId}:{subject}", value, context, $"rule={descriptor.RuleId}; value={value}");
                if (!baseline.IsFirstSeen) return null;
                matched = true;
                evidenceKinds.Add("baseline");
                evidence.Add($"baseline={baseline.Reason}; value={value}");
            }

            if (spec.Threshold > 0)
            {
                var key = $"{descriptor.RuleId}:{ScopeValue(spec.Scope, r)}";
                var count = !string.IsNullOrWhiteSpace(spec.DistinctField)
                    ? AddDistinct(PerKeyDistinct, key, DistinctValue(spec.DistinctField!, r), context.TimestampUtc, TimeSpan.FromSeconds(spec.WindowSeconds))
                    : AddTime(key, context.TimestampUtc, TimeSpan.FromSeconds(spec.WindowSeconds));
                if (count < spec.Threshold) return null;
                matched = true;
                evidenceKinds.Add("threshold");
                if (!string.IsNullOrWhiteSpace(spec.DistinctField)) evidenceKinds.Add("distinct");
                evidence.Add($"count={count}/{spec.WindowSeconds}s; threshold={spec.Threshold}");
            }

            AddPrecisionTelemetryKinds(descriptor.RuleId, r, evidenceKinds);

            if (!matched) return null;
            if (!RulePrecisionCatalog.HasRequiredRuntimeEvidence(descriptor.RuleId, spec.Severity, spec.Threshold, spec.DistinctField, evidenceKinds, r, out var precisionReason))
                return null;

            if (!string.IsNullOrWhiteSpace(precisionReason))
                evidence.Add(precisionReason);

            return Event(descriptor, context, spec.Severity, spec.Summary, string.Join("; ", evidence));
        }

        private static void AddPrecisionTelemetryKinds(string ruleId, TrafficRecord record, ISet<string> evidenceKinds)
        {
            var profile = RulePrecisionCatalog.GetProfile(ruleId);
            foreach (var kind in profile.RequiredTelemetry)
            {
                if (!RulePrecisionCatalog.HasTelemetryKind(kind, record)) continue;
                switch (kind)
                {
                    case RuleTelemetryKind.Http:
                        evidenceKinds.Add("http");
                        break;
                    case RuleTelemetryKind.Dns:
                        evidenceKinds.Add("dns");
                        break;
                    case RuleTelemetryKind.Tls:
                    case RuleTelemetryKind.Ja3:
                    case RuleTelemetryKind.Ja4:
                    case RuleTelemetryKind.Sni:
                        evidenceKinds.Add("tls");
                        break;
                    case RuleTelemetryKind.Identity:
                    case RuleTelemetryKind.Authentication:
                    case RuleTelemetryKind.Directory:
                    case RuleTelemetryKind.Microsoft365Audit:
                        evidenceKinds.Add("identity");
                        break;
                    case RuleTelemetryKind.CloudAudit:
                    case RuleTelemetryKind.DevOpsAudit:
                        evidenceKinds.Add("cloud-devops");
                        break;
                    case RuleTelemetryKind.KubernetesAudit:
                        evidenceKinds.Add("kubernetes");
                        break;
                    case RuleTelemetryKind.OtIcsProtocol:
                        evidenceKinds.Add("ot-ics");
                        break;
                    case RuleTelemetryKind.EngineHealth:
                        evidenceKinds.Add("engine-health");
                        break;
                    case RuleTelemetryKind.Process:
                        evidenceKinds.Add("process");
                        break;
                    case RuleTelemetryKind.Payload:
                    case RuleTelemetryKind.NormalizedPayload:
                        evidenceKinds.Add("payload");
                        break;
                    default:
                        evidenceKinds.Add("telemetry");
                        break;
                }
            }
        }

        private static bool LooksHttp(TrafficRecord r)
        {
            return !string.IsNullOrWhiteSpace(r.HttpMethod)
                || !string.IsNullOrWhiteSpace(r.HttpUri)
                || !string.IsNullOrWhiteSpace(r.HttpHost)
                || !string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                || !string.IsNullOrWhiteSpace(r.HttpUserAgent);
        }

        private static string ScopeValue(string scope, TrafficRecord r) => scope.ToLowerInvariant() switch
        {
            "source-destination" => $"{r.Source}->{r.Destination}",
            "destination" => r.Destination ?? "unknown-destination",
            "host" => BestHost(r),
            _ => r.Source ?? "unknown-source"
        };

        private static string DistinctValue(string field, TrafficRecord r) => field.ToLowerInvariant() switch
        {
            "host" => BestHost(r),
            "uri" => r.HttpUri ?? Text(r),
            "destination" => r.Destination ?? "unknown-destination",
            "port" => (r.DestinationPort ?? r.SourcePort ?? -1).ToString(System.Globalization.CultureInfo.InvariantCulture),
            "asn" => r.WhoisASN ?? "unknown-asn",
            "country" => FirstNonEmpty(r.DstCountryIso2, r.DstCountry, r.WhoisCountry) ?? "unknown-country",
            _ => Text(r)
        };

        private static double Ratio(string value, Func<char, bool> predicate)
        {
            if (string.IsNullOrWhiteSpace(value)) return 0;
            var letters = value.Where(char.IsLetter).ToArray();
            if (letters.Length == 0) return 0;
            return letters.Count(predicate) / (double)letters.Length;
        }

        private static int Threshold(RuleDescriptor descriptor, int defaultValue, int min = 1, int max = int.MaxValue) =>
            RuleEngine.GetRuleIntSetting(descriptor.RuleId, "Threshold", defaultValue, min, max);

        private static int WindowSeconds(RuleDescriptor descriptor, int defaultValue, int min = 1, int max = 86400) =>
            RuleEngine.GetRuleIntSetting(descriptor.RuleId, "WindowSeconds", defaultValue, min, max);

        private static double DoubleSetting(RuleDescriptor descriptor, string key, double defaultValue, double min, double max) =>
            RuleEngine.GetRuleDoubleSetting(descriptor.RuleId, key, defaultValue, min, max);

        private static DetectionEvent Event(RuleDescriptor d, RuleEvaluationContext c, SeverityLevel severity, string summary, string evidence)
        {
            var r = c.Record;
            var evt = new DetectionEvent
            {
                RuleId = d.RuleId,
                RuleName = d.Name,
                TimestampUtc = c.TimestampUtc,
                Severity = severity,
                SourceIp = r.Source,
                SourcePort = r.SourcePort,
                DestinationIp = r.Destination,
                DestinationHost = FirstNonEmpty(r.HttpHost, r.Sni, r.DnsQname),
                DestinationPort = r.DestinationPort,
                Protocol = FirstNonEmpty(r.ApplicationProtocol, r.ApplicationService, r.Protocol),
                ProcessName = r.ProcessName,
                Country = FirstNonEmpty(r.DstCountryIso2, r.DstCountry, r.WhoisCountry),
                Asn = r.WhoisASN,
                Ja4 = r.Ja4,
                Hassh = r.Hassh,
                QuicAlpn = r.QuicAlpn,
                QuicConnectionIdHash = r.QuicConnectionIdHash,
                PacketId = r.Id.ToString("N"),
                Summary = summary,
                Description = summary,
                Evidence = evidence,
                StructuredEvidence = EvidenceBuilder.FromLegacyEvidence(summary, evidence,
                    new DetectionEvidenceItem("source", r.Source ?? "unknown", "traffic-record"),
                    new DetectionEvidenceItem("destination", r.Destination ?? "unknown", "traffic-record"),
                    new DetectionEvidenceItem("protocol", FirstNonEmpty(r.ApplicationProtocol, r.ApplicationService, r.Protocol) ?? "unknown", "traffic-record")),
                Count = 1,
                WindowSeconds = 0,
                DeliveryStatus = DetectionDeliveryStatus.Pending,
                SuppressionStatus = DetectionSuppressionStatus.None
            };

            var intelligence = RuleIntelligenceFactory.CreateDefault(d);
            evt.RuleMaturityAtDetection = intelligence.Maturity.ToString();
            evt.RuleRevisionAtDetection = intelligence.Revision;
            ConfidenceBuilder.ApplyDefault(evt, d, intelligence);
            ApplyPrecisionProfileEvidence(evt, d);
            return evt;
        }

        private static void ApplyPrecisionProfileEvidence(DetectionEvent evt, RuleDescriptor descriptor)
        {
            var profile = RulePrecisionCatalog.GetProfile(descriptor);
            EvidenceBuilder.AppendEvidence(evt, "precision.maturity", profile.Maturity.ToString(), "rule-precision-profile");
            EvidenceBuilder.AppendEvidence(evt, "precision.defaultMode", profile.DefaultMode.ToString(), "rule-precision-profile");
            EvidenceBuilder.AppendEvidence(evt, "precision.minimumConfidence", profile.MinimumConfidence.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule-precision-profile");
            if (profile.Threshold.HasValue)
                EvidenceBuilder.AppendEvidence(evt, "precision.threshold", profile.Threshold.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule-precision-profile");
            if (profile.Window.HasValue)
                EvidenceBuilder.AppendEvidence(evt, "precision.windowSeconds", ((int)profile.Window.Value.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule-precision-profile");
            if (!string.IsNullOrWhiteSpace(profile.DistinctBy))
                EvidenceBuilder.AppendEvidence(evt, "precision.distinctBy", profile.DistinctBy!, "rule-precision-profile");
        }

        private static BaselineDecision ObserveBaseline(string kind, string subject, string value, RuleEvaluationContext c, string evidence)
        {
            try
            {
                return BaselineStore.Current.ObserveAsync(new BaselineObservation(kind, subject, value, c.TimestampUtc, evidence)).GetAwaiter().GetResult();
            }
            catch
            {
                return new BaselineDecision(false, true, false, "baseline unavailable", 0, null, null);
            }
        }

        private static void ConfidenceForPayload(DetectionEvent evt, string ruleId, NormalizedPayload payload)
        {
            var b = new ConfidenceBuilder();
            if (!string.IsNullOrWhiteSpace(payload.Normalized)) b.AddEvidence(0.35, "normalized-payload");
            if (ruleId == "R084" && payload.LowerInvariant.Contains("${jndi:")) b.AddEvidence(0.45, "direct-jndi-token");
            else if (ruleId == "R084" && payload.LowerInvariant.Contains("jndi")) b.AddEvidence(0.30, "jndi-token");
            else b.AddEvidence(evt.Severity is SeverityLevel.Critical ? 0.45 : 0.35, "payload-signature");
            b.ApplyTo(evt);
        }

        private static int AddTime(string key, DateTime now, TimeSpan window)
        {
            var list = PerKeyTimes.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.Add(now);
                list.RemoveAll(t => now - t > window);
                return list.Count;
            }
        }

        private static int AddDistinct(ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> dict, string key, string value, DateTime now, TimeSpan window)
        {
            var map = dict.GetOrAdd(key, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            map[value] = now;
            foreach (var kv in map.ToArray())
                if (now - kv.Value > window) map.TryRemove(kv.Key, out _);
            return map.Count;
        }

        private static long AddBytes(string key, DateTime now, int bytes, TimeSpan window)
        {
            var list = ByteWindows.GetOrAdd(key, _ => new List<(DateTime Ts, int Bytes)>());
            lock (list)
            {
                list.Add((now, Math.Max(0, bytes)));
                list.RemoveAll(x => now - x.Ts > window);
                return list.Sum(x => (long)x.Bytes);
            }
        }

        private static long SumBytes(string key, DateTime now, TimeSpan window)
        {
            if (!ByteWindows.TryGetValue(key, out var list)) return 0;
            lock (list)
            {
                list.RemoveAll(x => now - x.Ts > window);
                return list.Sum(x => (long)x.Bytes);
            }
        }

        private static string Text(TrafficRecord r) => string.Join(" ", new[]
        {
            r.Info, r.HttpMethod, r.HttpHost, r.HttpUri, r.HttpUserAgent, r.HttpRequestHeaders,
            r.Sni, r.Alpn, r.TlsVersion, r.DnsQname, r.DnsQtype, r.DnsRcode, r.DnsAnswers,
            r.ApplicationProtocol, r.ApplicationService, r.Protocol, r.ProcessName,
            r.WhoisRegistrar, r.WhoisOrganization, r.WhoisCountry, r.WhoisASN,
            r.CertIssuer, r.CertSubject, r.QuicAlpn
        }.Where(x => !string.IsNullOrWhiteSpace(x))!);

        private static string Short(string? s, int max = 320)
        {
            if (string.IsNullOrWhiteSpace(s)) return string.Empty;
            s = s.Replace('\r', ' ').Replace('\n', ' ').Trim();
            return s.Length <= max ? s : s[..max] + "…";
        }

        private static bool ContainsAny(string? text, params string[] needles)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            foreach (var n in needles)
                if (!string.IsNullOrWhiteSpace(n) && text.IndexOf(n, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            return false;
        }

        private static bool StartsWithAny(string? text, params string[] prefixes)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            return prefixes.Any(p => text.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        }

        private static bool EndsWithAny(string? text, params string[] suffixes)
        {
            if (string.IsNullOrWhiteSpace(text)) return false;
            return suffixes.Any(p => text.EndsWith(p, StringComparison.OrdinalIgnoreCase));
        }

        private static string? FirstNonEmpty(params string?[] values) => values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v));

        private static bool IsInternal(string? ipOrHost)
        {
            if (string.IsNullOrWhiteSpace(ipOrHost)) return false;
            var host = ipOrHost.Trim();
            if (!IPAddress.TryParse(host, out var ip))
                return host.EndsWith(".local", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".lan", StringComparison.OrdinalIgnoreCase) || host.EndsWith(".internal", StringComparison.OrdinalIgnoreCase);

            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || b[0] == 127 || (b[0] == 169 && b[1] == 254);
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                return ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || host.StartsWith("fc", StringComparison.OrdinalIgnoreCase) || host.StartsWith("fd", StringComparison.OrdinalIgnoreCase) || IPAddress.IsLoopback(ip);
            return false;
        }

        private static bool IsExternal(string? ipOrHost)
        {
            if (string.IsNullOrWhiteSpace(ipOrHost)) return false;
            return !IsInternal(ipOrHost);
        }

        private static string? NormalizeHost(string? host) => string.IsNullOrWhiteSpace(host) ? null : host.Trim().TrimEnd('.').ToLowerInvariant();
        private static string? NormalizeMac(string? mac) => string.IsNullOrWhiteSpace(mac) ? null : mac.Trim().ToUpperInvariant().Replace('-', ':');

        private static string BestHost(TrafficRecord r) => FirstNonEmpty(r.HttpHost, r.Sni, r.DnsQname, r.Destination) ?? string.Empty;

        private static string? DomainFromRecord(TrafficRecord r)
        {
            var q = FirstNonEmpty(r.DnsQname, r.HttpHost, r.Sni);
            if (string.IsNullOrWhiteSpace(q) && !string.IsNullOrWhiteSpace(r.Info))
            {
                var match = Regex.Match(r.Info, @"(?i)\b([a-z0-9][a-z0-9\-]{1,62}\.)+[a-z]{2,63}\b");
                if (match.Success) q = match.Value;
            }
            if (string.IsNullOrWhiteSpace(q)) return null;
            q = q.Trim().TrimEnd('.').ToLowerInvariant();
            return IPAddress.TryParse(q, out _) ? null : q;
        }

        private static string RootDomain(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return string.Empty;
            var h = host.Trim().TrimEnd('.').ToLowerInvariant();
            var parts = h.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length <= 2) return h;
            return parts[^2] + "." + parts[^1];
        }

        private static string SecondLevelLabel(string host)
        {
            var parts = host.Split('.', StringSplitOptions.RemoveEmptyEntries);
            return parts.Length >= 2 ? parts[^2] : host;
        }

        private static bool IsDns(TrafficRecord r) => string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase) || string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase) || r.SourcePort == 53 || r.DestinationPort == 53 || !string.IsNullOrWhiteSpace(r.DnsQname);
        private static bool IsMqtt(TrafficRecord r) => MqttPorts.Contains(r.SourcePort ?? -1) || MqttPorts.Contains(r.DestinationPort ?? -1) || ContainsAny(Text(r), "mqtt", "publish", "subscribe", "connect ack");
        private static bool IsUploadMethod(TrafficRecord r) => string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase) || string.Equals(r.HttpMethod, "PUT", StringComparison.OrdinalIgnoreCase) || string.Equals(r.HttpMethod, "PATCH", StringComparison.OrdinalIgnoreCase);
        private static bool IsUploadLike(TrafficRecord r) => IsUploadMethod(r) || Math.Max(r.Length, r.L4Len ?? 0) >= 500_000;

        private static bool LooksLikeKnownServer(string? host, string? process, string text) => ContainsAny(host, "srv", "server", "dc", "nas", "sql", "db") || ContainsAny(process, "nginx", "apache", "iis", "sqlservr", "postgres", "mysqld") || ContainsAny(text, "server role", "known server");

        private static bool IsCloudStorageHost(string? host) => ContainsAny(host, "drive.google.com", "docs.google.com", "dropbox.com", "onedrive", "sharepoint.com", "box.com", "icloud.com", "mega.nz", "pcloud", "mediafire", "wetransfer", "storage.googleapis.com", "blob.core.windows.net", "s3.amazonaws.com");
        private static bool IsGitRawHost(string host) => ContainsAny(host, "raw.githubusercontent.com", "gist.githubusercontent.com", "gitlab.com", "gitlabusercontent", "githubusercontent.com", "bitbucket.org");
        private static bool IsChatApiHost(string host) => ContainsAny(host, "api.telegram.org", "discord.com/api", "discordapp.com/api", "hooks.slack.com", "slack.com/api", "teams.microsoft.com");
        private static bool IsPasteOrDropHost(string host) => ContainsAny(host, "pastebin.com", "hastebin", "paste.rs", "ghostbin", "transfer.sh", "file.io", "gofile.io", "anonfiles", "pixeldrain", "catbox.moe", "tmpfiles.org", "wetransfer", "mega.nz");
        private static bool IsSaasHost(string host) => IsCloudStorageHost(host) || ContainsAny(host, "salesforce.com", "atlassian.net", "notion.so", "airtable.com", "hubspot", "zendesk", "servicenow", "dropbox", "sharepoint", "googleapis.com");

        private static bool PayloadContainsLog4Shell(string text) => ContainsAny(text, "${jndi:", "jndi:ldap", "jndi:rmi", "jndi:dns", "${${lower:j", "${lower:jn}", "ldap://", "rmi://") && ContainsAny(text, "jndi", "${");
        private static bool PayloadContainsSqlInjection(string text) => ContainsAny(text, " union select ", " or 1=1", "' or '1'='1", "information_schema", "sleep(", "benchmark(", "xp_cmdshell", "waitfor delay", "--", "/*") && ContainsAny(text, "select", "union", "where", "sleep", "or 1=1", "information_schema");
        private static bool PayloadContainsPathTraversal(string text) => ContainsAny(text, "../", "..\\", "%2e%2e%2f", "%252e%252e%252f", "/etc/passwd", "boot.ini", "win.ini", "WEB-INF/web.xml");
        private static bool PayloadContainsSerialization(string text) => ContainsAny(text, "rO0AB", "ysoserial", "ObjectDataProvider", "__type", "$type", "java.io.Serializable", "BinaryFormatter", "LosFormatter", "ViewState") && ContainsAny(text, "serialized", "rO0AB", "ysoserial", "ObjectDataProvider", "$type", "__type");
        private static bool PayloadContainsCommandInjection(string text) => ContainsAny(text, ";cat ", "|cat ", "&&", "||", "`", "$(`", "${IFS}", "cmd.exe", "/bin/sh", "/bin/bash", "whoami", "uname -a", "curl ", "wget ") && ContainsAny(text, ";", "|", "&&", "||", "`", "$(`", "cmd.exe", "/bin/sh", "whoami");
        private static bool PayloadContainsReverseShell(string text) => ContainsAny(text, "bash -i", "/dev/tcp/", "nc -e", "ncat -e", "socat exec", "powershell -enc", "meterpreter", "reverse shell", "Invoke-PowerShellTcp", "cmd /c powershell");
        private static bool PayloadContainsPowerShellCradle(string text) => ContainsAny(text, "powershell", "pwsh") && ContainsAny(text, "downloadstring", "invoke-webrequest", "iwr ", "webclient", "iex", "frombase64string", "-enc", "bitsadmin");

        private static double ShannonEntropy(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var groups = s.GroupBy(c => c).Select(g => (double)g.Count() / s.Length);
            return -groups.Sum(p => p * Math.Log(p, 2));
        }

        private static double VowelRatio(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            var letters = s.Where(char.IsLetter).ToArray();
            if (letters.Length == 0) return 0;
            return letters.Count(c => "aeiou".Contains(char.ToLowerInvariant(c))) / (double)letters.Length;
        }

        private static string? ExtractIpv6Target(string text)
        {
            var match = Regex.Match(text, @"(?i)\b(?:[0-9a-f]{1,4}:){2,}[0-9a-f]{0,4}\b");
            return match.Success ? match.Value : null;
        }

        private static string? ExtractTopic(string text)
        {
            var match = Regex.Match(text, @"(?i)topic\s*[:=]\s*(?<topic>[^\s,;]+)");
            return match.Success ? match.Groups["topic"].Value : null;
        }
    }
}
