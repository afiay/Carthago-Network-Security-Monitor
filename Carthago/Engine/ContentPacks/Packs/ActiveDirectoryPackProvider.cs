// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/Packs/ActiveDirectoryPackProvider.cs
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Services.Response;

namespace Carthago.Engine.ContentPacks.Packs
{
    internal sealed class ActiveDirectoryPackProvider : CompiledContentPackProviderBase
    {
        private static readonly IReadOnlyList<string> SourceRules = Concat(
            Range(73, 83),
            Range(123, 127),
            Range(188, 197),
            Range(286, 289),
            Range(333, 352)).ToArray();

        private readonly ContentPackManifest _manifest = new()
        {
            PackId = "carthago.active-directory.v1",
            Name = "Active Directory / Windows Enterprise Pack",
            Version = "1.0.0",
            Description = "Optional enterprise identity pack for Kerberos, LDAP, NTLM, SMB admin abuse, and Windows lateral-movement telemetry.",
            Category = "ActiveDirectoryWindows",
            Author = "Carthago",
            MinimumCarthagoVersion = "1.0.0",
            Rules = AliasRules("AD", SourceRules, "ActiveDirectoryWindows"),
            Profiles = Profiles(
                Profile("Enterprise", RuleMode.Alert, 0.75, "Enterprise defaults allow higher-confidence AD findings to page analysts.", "Approved.DomainControllers"),
                Profile("SmallBusiness", RuleMode.Shadow, null, "Keep AD signals visible without paging until DCs and admin hosts are approved.", "Approved.DomainControllers"),
                Profile("HomeLab", RuleMode.Disabled, null, "Disabled until configured because these detections assume domain-controller context.", "Approved.DomainControllers"),
                Profile("Research", RuleMode.Alert, 0.60, "Research broadens alerting for identity replay validation.", "Approved.DomainControllers")
            ),
            RequiredTelemetry = new List<string> { "Windows auth protocol metadata", "Kerberos and LDAP visibility", "admin-host inventory", "domain-controller enrichment" },
            ReplaySamples = Samples(
                Sample("ad-psremoting-encoded-command", @"Tests/RuleReplaySamples/malicious/ad-psremoting-encoded-command.json", Services.Benchmarking.ReplaySampleClassification.Malicious, "Positive sample for PowerShell remoting encoded-command lateral movement.", "AD041"),
                Sample("ad-benign-rdp-admin-host", @"Tests/RuleReplaySamples/benign/normal-admin-rdp-from-adminhost.json", Services.Benchmarking.ReplaySampleClassification.Benign, "Approved admin-host RDP should stay non-paging.")
            ),
            Benchmarks = BenchmarkExpectations(
                Benchmark("Enterprise", 0.70, 0),
                Benchmark("Research", 0.75, 1)
            ),
            HuntingQueries = Hunts(
                Hunt("ad-hunt-001", "RDP lateral movement", "Find RDP burst and clipboard-transfer style lateral movement.", "AD001", 0.65),
                Hunt("ad-hunt-002", "LDAP enumeration", "Find LDAP enumeration and password-policy reconnaissance.", "AD037", 0.65),
                Hunt("ad-hunt-003", "NTLM relay suspicion", "Review NTLM relay and external NTLM authentication indicators.", "AD010", 0.70),
                Hunt("ad-hunt-004", "Workstation-to-workstation admin protocols", "Review SMB/WinRM/WMI/DCOM admin traffic between workstations.", "AD031", 0.60)
            ),
            ResponseRecommendations = Recommendations(
                Recommend("ad-response-001", "Disable suspected account", "Recommend disabling or constraining the suspected account after identity-owner review.", ResponseActionType.MarkForReview, ResponseActionSafety.ApprovalRequired, "Identity actions require explicit approval and directory-owner coordination.", new[] { "AD020", "AD023", "AD029" }, "Review the account's recent sign-ins.", "Coordinate with the directory owner before disabling."),
                Recommend("ad-response-002", "Isolate host recommendation", "Recommend isolating the suspected workstation after evidence review.", ResponseActionType.RecommendIsolateHost, ResponseActionSafety.RecommendationOnly, "Do not auto-isolate hosts from content-pack recommendations.", new[] { "AD041", "AD045", "AD047" }, "Validate the source host role.", "Preserve memory and network evidence before containment."),
                Recommend("ad-response-003", "Check domain controller logs", "Recommend pulling domain-controller and auth-provider logs for corroboration.", ResponseActionType.ExportEvidenceBundle, ResponseActionSafety.Informational, "Evidence collection should stay read-only by default.", new[] { "AD033", "AD037", "AD040" }, "Collect DC security logs.", "Correlate with the journaled DetectionEvent IDs.")
            ),
            DashboardPresets = Presets(
                Preset("ad-dashboard-001", "Directory Lateral Movement", "Focuses on admin protocols, Kerberos, and LDAP reconnaissance.", "Enterprise", ("category", "ActiveDirectoryWindows")),
                Preset("ad-dashboard-002", "Research Identity Drift", "Broad replay-focused view for identity detection tuning.", "Research", ("packId", "carthago.active-directory.v1"))
            ),
            References = References(
                Ref("MITRE ATT&CK", "Remote Services", "https://attack.mitre.org/techniques/T1021/"),
                Ref("MITRE ATT&CK", "Steal or Forge Kerberos Tickets", "https://attack.mitre.org/techniques/T1558/", "T1558"),
                Ref("Sigma", "Windows lateral movement detection guidance", "https://sigmahq.io/docs/")
            ),
            Changelog = new List<string> { "1.0.0 - Initial compiled Active Directory and Windows enterprise pack release." },
            SafetyNotes = new List<string>
            {
                "Pack is disabled for HomeLab until domain-controller context is explicitly configured.",
                "Recommendations never perform automatic directory or host containment actions."
            },
            License = "MIT"
        };

        public override ContentPackManifest Manifest => _manifest;
    }
}
