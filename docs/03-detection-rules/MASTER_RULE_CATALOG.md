# Carthago — master detection-rule catalog

**Source-content digest:** `fcfc920472d1b6c4d748` · **Registered:** 965 unique R-series rules (`R001`–`R965`)

This is the **single central navigation catalog** for registered detection rules. Metadata is extracted from each rule's actual C# `RuleDescriptor` at the cited snapshot. Source registration is not proof that telemetry can reach the predicate, an alert is emitted, tests passed, or detection quality was field-validated.

**Verification column:** a candidate or zero-execution label is quoted from the linked batch's opening record; otherwise consult the dated batch and [development verification ledger](../DEVELOPMENT_VALIDATION_LEDGER.md). No application tests were run to generate this catalog. The original batch reports remain the authoritative historical evidence.

[All detection documentation](README.md) · [Rule documentation standard](../rules/RULE_DOCUMENTATION_STANDARD.md) · [Rule hardening progress](../RULE_HARDENING_PROGRESS.md) · [Research backlog](../rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md)

## Categories

| Detection category | Registered rules |
| --- | ---: |
| [AccountAccess](#accountaccess-1-rules) | 1 |
| [AccountDiscovery](#accountdiscovery-1-rules) | 1 |
| [ActiveDirectoryWindows](#activedirectorywindows-20-rules) | 20 |
| [AssetInventory](#assetinventory-10-rules) | 10 |
| [Availability](#availability-1-rules) | 1 |
| [Behavior](#behavior-1-rules) | 1 |
| [CloudDev](#clouddev-29-rules) | 29 |
| [CloudInfrastructure](#cloudinfrastructure-20-rules) | 20 |
| [CloudSaas](#cloudsaas-9-rules) | 9 |
| [Collection](#collection-4-rules) | 4 |
| [CommandAndControl](#commandandcontrol-21-rules) | 21 |
| [CommandControl](#commandcontrol-5-rules) | 5 |
| [ContainerDiscovery](#containerdiscovery-1-rules) | 1 |
| [ContainerExecution](#containerexecution-1-rules) | 1 |
| [DatabaseServiceExposure](#databaseserviceexposure-38-rules) | 38 |
| [DataLossStaging](#datalossstaging-22-rules) | 22 |
| [DefenseEvasion](#defenseevasion-1-rules) | 1 |
| [Detection-engine health](#detection-engine-health-7-rules) | 7 |
| [DevOpsSupplyChain](#devopssupplychain-20-rules) | 20 |
| [Discovery](#discovery-16-rules) | 16 |
| [DNS](#dns-7-rules) | 7 |
| [Dns](#dns-14-rules) | 14 |
| [DnsAdvanced](#dnsadvanced-35-rules) | 35 |
| [DnsThreat](#dnsthreat-5-rules) | 5 |
| [Egress](#egress-6-rules) | 6 |
| [EmailCollaboration](#emailcollaboration-20-rules) | 20 |
| [EvasionInfra](#evasioninfra-56-rules) | 56 |
| [EvasionTunnel](#evasiontunnel-61-rules) | 61 |
| [Execution](#execution-11-rules) | 11 |
| [Exfiltration](#exfiltration-13-rules) | 13 |
| [ExfiltrationAdvanced](#exfiltrationadvanced-39-rules) | 39 |
| [GeoIP](#geoip-1-rules) | 1 |
| [HTTP](#http-7-rules) | 7 |
| [HttpApi](#httpapi-90-rules) | 90 |
| [ICMP](#icmp-2-rules) | 2 |
| [Identity](#identity-1-rules) | 1 |
| [IdentityAccess](#identityaccess-28-rules) | 28 |
| [IdentityAdvanced](#identityadvanced-20-rules) | 20 |
| [Impact](#impact-1-rules) | 1 |
| [Industrial](#industrial-1-rules) | 1 |
| [InitialAccess](#initialaccess-7-rules) | 7 |
| [IotOt](#iotot-17-rules) | 17 |
| [IotOtAdvanced](#iototadvanced-57-rules) | 57 |
| [IPv6](#ipv6-6-rules) | 6 |
| [KubernetesContainer](#kubernetescontainer-20-rules) | 20 |
| [Lateral Movement](#lateral-movement-1-rules) | 1 |
| [LateralMovement](#lateralmovement-45-rules) | 45 |
| [LocalDiscoveryWireless](#localdiscoverywireless-21-rules) | 21 |
| [MalwareC2](#malwarec2-20-rules) | 20 |
| [Network](#network-10-rules) | 10 |
| [NetworkApplianceExposure](#networkapplianceexposure-21-rules) | 21 |
| [NetworkDiscovery](#networkdiscovery-7-rules) | 7 |
| [OtIcsDeep](#oticsdeep-21-rules) | 21 |
| [Payload](#payload-1-rules) | 1 |
| [Payloads](#payloads-10-rules) | 10 |
| [PlatformHealthAdvanced](#platformhealthadvanced-16-rules) | 16 |
| [Protocol](#protocol-1-rules) | 1 |
| [ProtocolIntelligence](#protocolintelligence-1-rules) | 1 |
| [QUIC](#quic-2-rules) | 2 |
| [Reconnaissance](#reconnaissance-1-rules) | 1 |
| [RemoteAccess](#remoteaccess-2-rules) | 2 |
| [SSH](#ssh-1-rules) | 1 |
| [Threat Intel](#threat-intel-2-rules) | 2 |
| [TLS](#tls-8-rules) | 8 |
| [TlsPki](#tlspki-17-rules) | 17 |
| [WebAttack](#webattack-1-rules) | 1 |
| [WebThreat](#webthreat-3-rules) | 3 |

## Browse rule documentation

Select a category below, then expand any rule to view its documentation **on this page**. GitHub supports these native expandable sections without JavaScript. Use the category links above to jump directly to a group. Each entry is generated from its C# descriptor, with links to the authoritative batch evidence; authored tests are not proof of test execution.

### AccountAccess: 1 rules

<details>
<summary>Choose a rule from 1 AccountAccess entries</summary>

<details>
<summary><strong>R808 — ldapmodify-attributed Kerberos then LDAP service SYN sequence</strong> · Medium</summary>

- **Description:** ldapmodify-attributed Kerberos then LDAP service SYN sequence. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** AccountAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R808_LdapmodifyKerberosThenLdapSynRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### AccountDiscovery: 1 rules

<details>
<summary>Choose a rule from 1 AccountDiscovery entries</summary>

<details>
<summary><strong>R823 — dscl-attributed private LDAP/389 then LDAPS/636 SYN</strong> · Medium</summary>

- **Description:** dscl-attributed private LDAP/389 then LDAPS/636 SYN. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** AccountDiscovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R823_DsclLdapThenLdapsSynRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### ActiveDirectoryWindows: 20 rules

<details>
<summary>Choose a rule from 20 ActiveDirectoryWindows entries</summary>

<details>
<summary><strong>R333 — SMB Null Session Enumeration</strong> · High</summary>

- **Description:** Candidate R333 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R333_SMBNullSessionEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [331-335](batches/RULE_BATCH_331-335.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R334 — SMB Named Pipe Enumeration Burst</strong> · Medium</summary>

- **Description:** Candidate R334 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** ActiveDirectoryWindows
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R334_SMBNamedPipeEnumerationBurstRule.cs)
- **Detailed evidence and test scenarios:** [331-335](batches/RULE_BATCH_331-335.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R335 — LSARPC SAMR Enumeration Pattern</strong> · High</summary>

- **Description:** Candidate R335 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R335_LSARPCSAMREnumerationPatternRule.cs)
- **Detailed evidence and test scenarios:** [331-335](batches/RULE_BATCH_331-335.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R336 — DRSUAPI Replication Attempt</strong> · Critical</summary>

- **Description:** Candidate R336 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** ActiveDirectoryWindows
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R336_DRSUAPIReplicationAttemptRule.cs)
- **Detailed evidence and test scenarios:** [336-340](batches/RULE_BATCH_336-340.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R337 — Kerberos S4U Delegation Abuse Indicator</strong> · High</summary>

- **Description:** Candidate R337 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R337_KerberosS4UDelegationAbuseIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [336-340](batches/RULE_BATCH_336-340.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R338 — Kerberos RC4 Downgrade Indicator</strong> · Medium</summary>

- **Description:** Candidate R338 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** ActiveDirectoryWindows
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R338_KerberosRC4DowngradeIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [336-340](batches/RULE_BATCH_336-340.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R339 — SMB Signing Disabled Sensitive Host</strong> · High</summary>

- **Description:** Candidate R339 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R339_SMBSigningDisabledSensitiveHostRule.cs)
- **Detailed evidence and test scenarios:** [336-340](batches/RULE_BATCH_336-340.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R340 — Remote Registry Service Access</strong> · Medium</summary>

- **Description:** Candidate R340 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** ActiveDirectoryWindows
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R340_RemoteRegistryServiceAccessRule.cs)
- **Detailed evidence and test scenarios:** [336-340](batches/RULE_BATCH_336-340.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R341 — Scheduled Task Remote Creation Pattern</strong> · High</summary>

- **Description:** Candidate R341 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R341_ScheduledTaskRemoteCreationPatternRule.cs)
- **Detailed evidence and test scenarios:** [341-345](batches/RULE_BATCH_341-345.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R342 — Windows Admin Center Exposure Probe</strong> · High</summary>

- **Description:** Candidate R342 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R342_WindowsAdminCenterExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [341-345](batches/RULE_BATCH_341-345.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R343 — PowerShell Remoting Encoded Command</strong> · High</summary>

- **Description:** Candidate R343 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R343_PowerShellRemotingEncodedCommandRule.cs)
- **Detailed evidence and test scenarios:** [341-345](batches/RULE_BATCH_341-345.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R344 — WMI Event Subscription Remote Pattern</strong> · High</summary>

- **Description:** Candidate R344 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R344_WMIEventSubscriptionRemotePatternRule.cs)
- **Detailed evidence and test scenarios:** [341-345](batches/RULE_BATCH_341-345.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R345 — DCOM MMC20 Lateral Indicator</strong> · High</summary>

- **Description:** Candidate R345 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R345_DCOMMMC20LateralIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [341-345](batches/RULE_BATCH_341-345.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R346 — MSSQL xp_cmdshell Use Indicator</strong> · Critical</summary>

- **Description:** Candidate R346 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R346_MSSQLXpCmdshellUseIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [346-350](batches/RULE_BATCH_346-350.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R347 — MSSQL Linked Server Enumeration</strong> · Medium</summary>

- **Description:** Candidate R347 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R347_MSSQLLinkedServerEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [346-350](batches/RULE_BATCH_346-350.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R348 — LDAP AdminSDHolder Recon</strong> · Medium</summary>

- **Description:** Candidate R348 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R348_LDAPAdminSDHolderReconRule.cs)
- **Detailed evidence and test scenarios:** [346-350](batches/RULE_BATCH_346-350.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R349 — LDAP Kerberoast SPN Enumeration</strong> · High</summary>

- **Description:** Candidate R349 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R349_LDAPKerberoastSPNEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [346-350](batches/RULE_BATCH_346-350.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R350 — LDAP Password Policy Recon</strong> · Low</summary>

- **Description:** Candidate R350 requires verified operation and provenance; packet-only indicators return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R350_LDAPPasswordPolicyReconRule.cs)
- **Detailed evidence and test scenarios:** [346-350](batches/RULE_BATCH_346-350.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R351 — NTLM Authentication To External Host</strong> · High</summary>

- **Description:** Detects NTLM Authentication To External Host only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R351_NTLMAuthenticationToExternalHostRule.cs)
- **Detailed evidence and test scenarios:** [351-355](batches/RULE_BATCH_351-355.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R352 — LLMNR NBNS Responder Tool Indicator</strong> · High</summary>

- **Description:** Detects LLMNR NBNS Responder Tool Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** ActiveDirectoryWindows
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R352_LLMNRNBNSResponderToolIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [351-355](batches/RULE_BATCH_351-355.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### AssetInventory: 10 rules

<details>
<summary>Choose a rule from 10 AssetInventory entries</summary>

<details>
<summary><strong>R057 — New Device Appeared on Network</strong> · Low</summary>

- **Description:** Corroborated local-link inventory observation; no unauthorized-device assertion.
- **Category:** AssetInventory
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R057_NewDeviceAppearedOnNetworkRule.cs)
- **Detailed evidence and test scenarios:** [056-060](batches/RULE_BATCH_056-060.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R058 — New MAC Vendor Seen</strong> · Low</summary>

- **Description:** Corroborated local-link inventory observation; no unauthorized-device assertion.
- **Category:** AssetInventory
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R058_NewMACVendorSeenRule.cs)
- **Detailed evidence and test scenarios:** [056-060](batches/RULE_BATCH_056-060.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R059 — Same MAC Using Multiple IPs</strong> · Medium</summary>

- **Description:** Corroborated local-link inventory observation; no unauthorized-device assertion.
- **Category:** AssetInventory
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R059_SameMACUsingMultipleIPsRule.cs)
- **Detailed evidence and test scenarios:** [056-060](batches/RULE_BATCH_056-060.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R060 — Same IP Used by Multiple MACs</strong> · Medium</summary>

- **Description:** Corroborated local-link inventory observation; no unauthorized-device assertion.
- **Category:** AssetInventory
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R060_SameIPUsedByMultipleMACsRule.cs)
- **Detailed evidence and test scenarios:** [056-060](batches/RULE_BATCH_056-060.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R061 — Sensitive Host Communicating Externally</strong> · Medium</summary>

- **Description:** Evidence-driven asset observation, not an authorization verdict.
- **Category:** AssetInventory
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R061_SensitiveHostCommunicatingExternallyRule.cs)
- **Detailed evidence and test scenarios:** [061-065](batches/RULE_BATCH_061-065.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R062 — New Service Opened on Internal Host</strong> · Medium</summary>

- **Description:** Evidence-driven asset observation, not an authorization verdict.
- **Category:** AssetInventory
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R062_NewServiceOpenedOnInternalHostRule.cs)
- **Detailed evidence and test scenarios:** [061-065](batches/RULE_BATCH_061-065.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R063 — Workstation Acting Like Server</strong> · Medium</summary>

- **Description:** Evidence-driven asset observation, not an authorization verdict.
- **Category:** AssetInventory
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R063_WorkstationActingLikeServerRule.cs)
- **Detailed evidence and test scenarios:** [061-065](batches/RULE_BATCH_061-065.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R064 — First-Time Destination for Host</strong> · Low</summary>

- **Description:** Evidence-driven asset observation, not an authorization verdict.
- **Category:** AssetInventory
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R064_FirstTimeDestinationForHostRule.cs)
- **Detailed evidence and test scenarios:** [061-065](batches/RULE_BATCH_061-065.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R065 — First-Time ASN for Host</strong> · Low</summary>

- **Description:** Evidence-driven asset observation, not an authorization verdict.
- **Category:** AssetInventory
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R065_FirstTimeASNForHostRule.cs)
- **Detailed evidence and test scenarios:** [061-065](batches/RULE_BATCH_061-065.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R066 — First-Time Country for Host</strong> · Low</summary>

- **Description:** Corroborated first-seen destination country against a ready durable baseline; not a country-risk verdict.
- **Category:** AssetInventory
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/AssetInventory/R066_FirstTimeCountryForHostRule.cs)
- **Detailed evidence and test scenarios:** [066-070](batches/RULE_BATCH_066-070.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Availability: 1 rules

<details>
<summary>Choose a rule from 1 Availability entries</summary>

<details>
<summary><strong>R874 — Private OT TCP/502 SYN burst with unique packets</strong> · Medium</summary>

- **Description:** Eight distinct private-to-private TCP/502 SYN packets to the same peer within 30s; this is only a packet-rate shape, not device counter evidence, dropped traffic or proven denial of service.
- **Category:** Availability
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R874_PrivateOtTcpSynBurstRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Behavior: 1 rules

<details>
<summary>Choose a rule from 1 Behavior entries</summary>

<details>
<summary><strong>R007 — C2 Beaconing</strong> · Low</summary>

- **Description:** Command-and-control beaconing pattern
- **Category:** Behavior
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R007_C2BeaconingRule.cs)
- **Detailed evidence and test scenarios:** [006-010](batches/RULE_BATCH_006-010.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### CloudDev: 29 rules

<details>
<summary>Choose a rule from 29 CloudDev entries</summary>

<details>
<summary><strong>R198 — AWS Metadata Credential Retrieval</strong> · Critical</summary>

- **Description:** Detects direct IMDS credential-path access on AWS metadata targets, while suppressing expected cloud agent activity.
- **Category:** CloudDev
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R198_AwsMetadataCredentialRetrievalRule.cs)
- **Detailed evidence and test scenarios:** [196-200](batches/RULE_BATCH_196-200.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R199 — GCP Metadata Credential Retrieval</strong> · Critical</summary>

- **Description:** Detects Google metadata token or identity retrieval requests with the required metadata headers, while suppressing expected guest-agent activity.
- **Category:** CloudDev
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R199_GcpMetadataCredentialRetrievalRule.cs)
- **Detailed evidence and test scenarios:** [196-200](batches/RULE_BATCH_196-200.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R200 — Azure Metadata Credential Retrieval</strong> · Critical</summary>

- **Description:** Detects Azure IMDS token requests with the required metadata header and token path, while suppressing expected guest-agent activity.
- **Category:** CloudDev
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R200_AzureMetadataCredentialRetrievalRule.cs)
- **Detailed evidence and test scenarios:** [196-200](batches/RULE_BATCH_196-200.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R201 — Kubernetes Service Account Token Access</strong> · Critical</summary>

- **Description:** Detects non-platform access to mounted Kubernetes service-account tokens or the TokenRequest API, while suppressing expected Kubernetes components.
- **Category:** CloudDev
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R201_KubernetesServiceAccountTokenAccessRule.cs)
- **Detailed evidence and test scenarios:** [201-205](batches/RULE_BATCH_201-205.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R202 — Docker Registry Push Pull Anomaly</strong> · Medium</summary>

- **Description:** Detects repeated Docker Registry API push or pull operations against first-seen non-official external registries, rather than any /v2/ path mention.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R202_DockerRegistryPushPullAnomalyRule.cs)
- **Detailed evidence and test scenarios:** [201-205](batches/RULE_BATCH_201-205.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R203 — Container Image Layer Bulk Download</strong> · Medium</summary>

- **Description:** Detects bursts of distinct container layer downloads from first-seen non-official registries, instead of any blob or digest text.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R203_ContainerImageLayerBulkDownloadRule.cs)
- **Detailed evidence and test scenarios:** [201-205](batches/RULE_BATCH_201-205.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R204 — Terraform State File Access</strong> · High</summary>

- **Description:** Detects direct access to Terraform state artifacts instead of matching any mention of tfstate or backend configuration text.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R204_TerraformStateFileAccessRule.cs)
- **Detailed evidence and test scenarios:** [201-205](batches/RULE_BATCH_201-205.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R205 — CI CD Secret Token In URL</strong> · High</summary>

- **Description:** Detects concrete CI/CD secret token parameters embedded in URL query strings instead of broad pipeline keyword matches.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R205_CiCdSecretTokenInUrlRule.cs)
- **Detailed evidence and test scenarios:** [201-205](batches/RULE_BATCH_201-205.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R206 — Git Clone From Unknown External Host</strong> · Medium</summary>

- **Description:** Detects smart-HTTP Git clone traffic to first-seen non-official external hosts instead of any git-upload-pack text.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R206_GitCloneFromUnknownExternalHostRule.cs)
- **Detailed evidence and test scenarios:** [206-210](batches/RULE_BATCH_206-210.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R207 — Git Push To Unknown External Host</strong> · High</summary>

- **Description:** Detects Git smart-HTTP push traffic to first-seen non-official external hosts instead of any git-receive-pack text.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R207_GitPushToUnknownExternalHostRule.cs)
- **Detailed evidence and test scenarios:** [206-210](batches/RULE_BATCH_206-210.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R208 — Package Manager To Suspicious Registry</strong> · Medium</summary>

- **Description:** Detects package-manager traffic to first-seen non-official external registry hosts instead of matching generic registry words.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R208_PackageManagerToSuspiciousRegistryRule.cs)
- **Detailed evidence and test scenarios:** [206-210](batches/RULE_BATCH_206-210.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R209 — NPM Install Script Beacon Pattern</strong> · High</summary>

- **Description:** Detects outbound npm or node install-script beaconing to non-official external hosts instead of matching generic postinstall text.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R209_NpmInstallScriptBeaconPatternRule.cs)
- **Detailed evidence and test scenarios:** [206-210](batches/RULE_BATCH_206-210.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R210 — PyPI Package Download From Rare Domain</strong> · Medium</summary>

- **Description:** Detects pip or poetry artifact downloads from first-seen non-official Python package hosts instead of any pypi string mention.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R210_PypiPackageDownloadFromRareDomainRule.cs)
- **Detailed evidence and test scenarios:** [206-210](batches/RULE_BATCH_206-210.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R211 — PowerShell Gallery External Script Pull</strong> · High</summary>

- **Description:** Detects PowerShell-driven external script pulls from non-gallery hosts instead of broad install-module or downloadstring keyword matches.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R211_PowershellGalleryExternalScriptPullRule.cs)
- **Detailed evidence and test scenarios:** [211-215](batches/RULE_BATCH_211-215.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R212 — Curl Wget Raw Script To Shell</strong> · Critical</summary>

- **Description:** Detects curl or wget style pipe-to-shell retrieval from raw script sources instead of any mention of curl, wget, or GitHub raw text.
- **Category:** CloudDev
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R212_CurlWgetRawScriptToShellRule.cs)
- **Detailed evidence and test scenarios:** [211-215](batches/RULE_BATCH_211-215.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R213 — Cloud Storage Presigned URL Mass Access</strong> · High</summary>

- **Description:** Detects bursts of provider-specific presigned URL access against cloud storage, instead of matching any generic signature parameter text.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R213_CloudStoragePresignedUrlMassAccessRule.cs)
- **Detailed evidence and test scenarios:** [211-215](batches/RULE_BATCH_211-215.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R214 — S3 Bucket Listing Probe</strong> · Medium</summary>

- **Description:** Detects concrete S3 bucket listing semantics such as list-type=2 or prefix enumeration instead of any S3 keyword match.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R214_S3BucketListingProbeRule.cs)
- **Detailed evidence and test scenarios:** [211-215](batches/RULE_BATCH_211-215.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R215 — Azure Blob Container Enumeration</strong> · Medium</summary>

- **Description:** Detects concrete Azure Blob container listing semantics instead of any blob.core.windows.net or comp=list text match.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R215_AzureBlobContainerEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [211-215](batches/RULE_BATCH_211-215.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R216 — Google Storage Bucket Enumeration</strong> · Medium</summary>

- **Description:** Detects concrete Google Cloud Storage listing semantics instead of broad storage.googleapis.com text matches.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R216_GoogleStorageBucketEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [216-220](batches/RULE_BATCH_216-220.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R217 — Slack Webhook Exfiltration</strong> · High</summary>

- **Description:** Detects POST requests to Slack webhook or file/message upload APIs from non-collaboration processes, instead of any generic Slack host match.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R217_SlackWebhookExfiltrationRule.cs)
- **Detailed evidence and test scenarios:** [216-220](batches/RULE_BATCH_216-220.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R218 — Discord Webhook File Upload</strong> · High</summary>

- **Description:** Detects concrete Discord webhook or attachment upload requests with file-transfer context, while suppressing ordinary Discord client traffic and loose hostname matches.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R218_DiscordWebhookFileUploadRule.cs)
- **Detailed evidence and test scenarios:** [216-220](batches/RULE_BATCH_216-220.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R219 — Telegram Bot API Send Document</strong> · High</summary>

- **Description:** Detects exact Telegram Bot API sendDocument requests with document-upload context, instead of any generic api.telegram.org or sendMessage traffic.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R219_TelegramBotApiSendDocumentRule.cs)
- **Detailed evidence and test scenarios:** [216-220](batches/RULE_BATCH_216-220.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R220 — Paste Service High Volume POST</strong> · High</summary>

- **Description:** Detects repeated or non-trivial POST, PUT, or PATCH requests to paste or file-drop services, while suppressing simple page views and low-context browser traffic.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R220_PasteServiceHighVolumePostRule.cs)
- **Detailed evidence and test scenarios:** [216-220](batches/RULE_BATCH_216-220.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R221 — Remote Desktop SaaS Tool Beacon</strong> · Medium</summary>

- **Description:** Detects repeated beacons to first-seen remote-support SaaS infrastructure when host, process, or service context points to AnyDesk, TeamViewer, ScreenConnect, ConnectWise, Splashtop, or RustDesk.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R221_RemoteDesktopSaasToolBeaconRule.cs)
- **Detailed evidence and test scenarios:** [221-225](batches/RULE_BATCH_221-225.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R222 — Unauthorized Overlay Network Egress</strong> · High</summary>

- **Description:** Detects repeated first-seen overlay, tunnel, or mesh-network egress when process, host, or known service-port context points to Tailscale, ZeroTier, ngrok, Cloudflare Tunnel, or WireGuard.
- **Category:** CloudDev
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R222_UnauthorizedOverlayNetworkEgressRule.cs)
- **Detailed evidence and test scenarios:** [221-225](batches/RULE_BATCH_221-225.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R656 — Attributed Git smart-HTTP push request to official code host</strong> · Medium</summary>

- **Description:** Attributed Git smart-HTTP push request to official code host. R207 requires a first-seen unofficial remote host; this candidate requires a Git-attributed request to official GitHub/GitLab with /git-receive-pack, not a repository-exfiltration outcome.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R656_OfficialGitRemoteProcessSmartHttpPushRequestRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R717 — Script or curl process POST to GitHub/GitLab repository API</strong> · Medium</summary>

- **Description:** A PowerShell, curl, or Python process is associated with a cleartext outbound HTTP POST to a GitHub or GitLab repository API route. File reads, request-body contents, authentication, accepted upload, repository modification, and exfiltration are not observed.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R717_ScriptProcessCodeRepositoryApiPostRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R751 — macOS-characteristic process code-repository TLS payload burst</strong> · Medium</summary>

- **Description:** osascript, curl, git, Microsoft Word, or Microsoft Excel is associated with four substantial TLS/443 payload observations to GitHub, GitLab, or Bitbucket within two minutes. Repository API method, authentication, git operation, local file source and exfiltration are not observed.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R751_MacProcessCodeRepositoryTlsPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R756 — ESXi management-process code-repository TLS payload burst</strong> · Medium</summary>

- **Description:** hostd, vpxa, or vmx is associated with four substantial TLS/443 payload observations to GitHub, GitLab, or Bitbucket within two minutes. Datastore reads, HTTPS method, authentication, repository operation, unique TCP bytes and exfiltration are not observed.
- **Category:** CloudDev
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R756_EsxiManagementProcessCodeRepositoryTlsBurstRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### CloudInfrastructure: 20 rules

<details>
<summary>Choose a rule from 20 CloudInfrastructure entries</summary>

<details>
<summary><strong>R373 — AWS STS AssumeRole Burst</strong> · High</summary>

- **Description:** Detects AWS STS AssumeRole Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R373_AWSSTSAssumeRoleBurstRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R374 — AWS IAM AccessKey In URL</strong> · Critical</summary>

- **Description:** Detects AWS IAM AccessKey In URL only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R374_AWSIAMAccessKeyInURLRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R375 — AWS S3 ListBuckets External</strong> · Medium</summary>

- **Description:** Detects AWS S3 ListBuckets External only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R375_AWSS3ListBucketsExternalRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R376 — AWS S3 GetObject Bulk Download</strong> · High</summary>

- **Description:** Detects AWS S3 GetObject Bulk Download only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R376_AWSS3GetObjectBulkDownloadRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R377 — AWS EC2 UserData Metadata Probe</strong> · Critical</summary>

- **Description:** Detects AWS EC2 UserData Metadata Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R377_AWSEC2UserDataMetadataProbeRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R378 — AWS Lambda Invoke Burst</strong> · Medium</summary>

- **Description:** Detects AWS Lambda Invoke Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R378_AWSLambdaInvokeBurstRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R379 — AWS CloudTrail StopLogging Indicator</strong> · Critical</summary>

- **Description:** Detects AWS CloudTrail StopLogging Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R379_AWSCloudTrailStopLoggingIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R380 — AWS GuardDuty Finding Exfil Indicator</strong> · High</summary>

- **Description:** Detects AWS GuardDuty Finding Exfil Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R380_AWSGuardDutyFindingExfilIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R381 — Azure ARM Token Request Burst</strong> · Critical</summary>

- **Description:** Detects Azure ARM Token Request Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R381_AzureARMTokenRequestBurstRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R382 — Azure KeyVault Secret Enumeration</strong> · Critical</summary>

- **Description:** Detects Azure KeyVault Secret Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R382_AzureKeyVaultSecretEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R383 — Azure Storage SAS Token In URL</strong> · Critical</summary>

- **Description:** Detects Azure Storage SAS Token In URL only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R383_AzureStorageSASTokenInURLRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R384 — Azure IMDS Token Request</strong> · Critical</summary>

- **Description:** Detects Azure IMDS Token Request only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R384_AzureIMDSTokenRequestRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R385 — GCP OAuth Scope Broad Request</strong> · High</summary>

- **Description:** Detects GCP OAuth Scope Broad Request only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R385_GCPOAuthScopeBroadRequestRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R386 — GCP Storage SignedURL Mass Access</strong> · High</summary>

- **Description:** Detects GCP Storage SignedURL Mass Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R386_GCPStorageSignedURLMassAccessRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R387 — GCP ServiceAccount Key Download</strong> · Critical</summary>

- **Description:** Detects GCP ServiceAccount Key Download only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R387_GCPServiceAccountKeyDownloadRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R388 — Cloudflare Tunnel Creation Indicator</strong> · High</summary>

- **Description:** Detects Cloudflare Tunnel Creation Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R388_CloudflareTunnelCreationIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R389 — Ngrok Tunnel Creation Or Auth</strong> · High</summary>

- **Description:** Detects Ngrok Tunnel Creation Or Auth only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R389_NgrokTunnelCreationOrAuthRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R390 — Tailscale Tailnet Auth Indicator</strong> · Medium</summary>

- **Description:** Detects Tailscale Tailnet Auth Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R390_TailscaleTailnetAuthIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [381-390](batches/RULE_BATCH_381-390.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R391 — ZeroTier Network Join Indicator</strong> · Medium</summary>

- **Description:** Detects ZeroTier Network Join Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R391_ZeroTierNetworkJoinIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R392 — Public Cloud CLI UserAgent From Server</strong> · Medium</summary>

- **Description:** Detects Public Cloud CLI UserAgent From Server only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** CloudInfrastructure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R392_PublicCloudCLIUserAgentFromServerRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### CloudSaas: 9 rules

<details>
<summary>Choose a rule from 9 CloudSaas entries</summary>

<details>
<summary><strong>R104 — First-Time Cloud Storage Upload</strong> · Medium</summary>

- **Description:** Detects a first-seen upload from an internal source to a cloud storage provider when the request includes clear upload context, provider classification, and baseline evidence.
- **Category:** CloudSaas
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R104_FirstTimeCloudStorageUploadRule.cs)
- **Detailed evidence and test scenarios:** [101-105](batches/RULE_BATCH_101-105.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R105 — Large Upload to Personal Cloud Provider</strong> · High</summary>

- **Description:** Detects large or sustained outbound uploads to personal or unmanaged cloud storage providers, with stronger thresholds for enterprise-sync style hosts.
- **Category:** CloudSaas
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R105_LargeUploadToPersonalCloudProviderRule.cs)
- **Detailed evidence and test scenarios:** [101-105](batches/RULE_BATCH_101-105.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R106 — Upload After Internal Sweep</strong> · Critical</summary>

- **Description:** Detects outbound uploads that follow an internal administrative sweep from the same source, using self-contained sweep state instead of generic host-only matching.
- **Category:** CloudSaas
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R106_UploadAfterInternalSweepRule.cs)
- **Detailed evidence and test scenarios:** [106-110](batches/RULE_BATCH_106-110.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R107 — Exfiltration Split Across Many Destinations</strong> · High</summary>

- **Description:** Detects suspicious outbound transfer volume deliberately spread across multiple external destinations, while suppressing ordinary browsing fan-out.
- **Category:** CloudSaas
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R107_ExfiltrationSplitAcrossManyDestinationsRule.cs)
- **Detailed evidence and test scenarios:** [106-110](batches/RULE_BATCH_106-110.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R108 — Excessive Upload Ratio Per Host</strong> · High</summary>

- **Description:** Measures outbound-versus-inbound byte ratio per source and provider within a bounded window, rather than accumulating unbounded volume per source.
- **Category:** CloudSaas
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R108_ExcessiveUploadRatioPerHostRule.cs)
- **Detailed evidence and test scenarios:** [106-110](batches/RULE_BATCH_106-110.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R109 — Suspicious GitHub / GitLab Raw Access</strong> · Medium</summary>

- **Description:** Detects suspicious access to raw Git or gist content when the request shape, payload path, automation context, or repetition makes it more than routine repository browsing.
- **Category:** CloudSaas
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R109_SuspiciousGitHubGitLabRawAccessRule.cs)
- **Detailed evidence and test scenarios:** [106-110](batches/RULE_BATCH_106-110.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R110 — Telegram / Discord / Slack API Egress</strong> · High</summary>

- **Description:** Detects suspicious chat-platform API or webhook egress when the host and URI map to actual message, file, or webhook paths rather than generic collaboration traffic.
- **Category:** CloudSaas
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R110_TelegramDiscordSlackAPIEgressRule.cs)
- **Detailed evidence and test scenarios:** [106-110](batches/RULE_BATCH_106-110.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R111 — Paste Site / File Drop Service Egress</strong> · High</summary>

- **Description:** Detects suspicious paste-site or file-drop egress when the request shape indicates posting or uploading rather than ordinary viewing or landing-page traffic.
- **Category:** CloudSaas
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R111_PasteSiteFileDropServiceEgressRule.cs)
- **Detailed evidence and test scenarios:** [111-115](batches/RULE_BATCH_111-115.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R112 — SaaS Export-Like Traffic Pattern</strong> · High</summary>

- **Description:** Detects SaaS export-like API or workflow traffic when the destination is a business SaaS host and the request contains explicit export semantics plus meaningful transfer context.
- **Category:** CloudSaas
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/CloudSaas/R112_SaaSExportLikeTrafficPatternRule.cs)
- **Detailed evidence and test scenarios:** [111-115](batches/RULE_BATCH_111-115.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Collection: 4 rules

<details>
<summary>Choose a rule from 4 Collection entries</summary>

<details>
<summary><strong>R813 — PowerShell HTTP enumeration of four distinct external API resources</strong> · Medium</summary>

- **Description:** PowerShell HTTP enumeration of four distinct external API resources. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** Collection
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R813_PowershellPublicApiPathEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R814 — PowerShell external media GET followed by different-peer TLS/8443 payload</strong> · Medium</summary>

- **Description:** PowerShell external media GET followed by different-peer TLS/8443 payload. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** Collection
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R814_PowershellMediaGetThenUnusualTlsEgressRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R816 — curl-attributed distinct Confluence-style page API GET burst</strong> · Medium</summary>

- **Description:** curl-attributed distinct Confluence-style page API GET burst. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** Collection
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R816_ConfluenceApiDistinctPageGetRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R884 — Git-attributed private repository HTTP object GET fanout</strong> · Medium</summary>

- **Description:** git-attributed HTTP GET visits four distinct .git/objects paths on one private server within 60s; authenticated SaaS principal, repository confidentiality and unusual download volume are not established.
- **Category:** Collection
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R884_GitPrivateObjectGetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### CommandAndControl: 21 rules

<details>
<summary>Choose a rule from 21 CommandAndControl entries</summary>

<details>
<summary><strong>R856 — Frpc public TCP/7000 SYN then payload</strong> · Medium</summary>

- **Description:** A frpc-attributed public TCP/7000 SYN precedes same-peer payload within 30s; CLI options, relay use and connection success unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R856_FrpcPublicTcp7000SynThenPayloadRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R862 — Rundll32 DNS TXT query followed by matching-name TLS SNI</strong> · Medium</summary>

- **Description:** Same locally attributed rundll32 PID makes a public DNS/TXT query then a public TLS/443 packet with matching SNI within 60s; queried content and C2 unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R862_Rundll32DnsTxtThenSameNameTlsRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R870 — ESXi hostd-attributed repeated public HTTP GET polling</strong> · Medium</summary>

- **Description:** Four hostd-attributed GET requests to one public web-service polling URI within 40s; one-way C2, remote commands and ESXi role are not established.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R870_HostdPublicHttpPollBurstRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R882 — ESXi utility public script GET then other-peer HTTP check-in POST</strong> · Medium</summary>

- **Description:** esxcli-attributed public HTTP GET for a .sh path precedes busybox-attributed HTTP check-in POST to a different public IP from the same private host within 60s; no process lineage, execution or C2 proved.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R882_EsxiGetThenOtherPeerPostRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R883 — VMware VMX-attributed TLS/8443 to three public peers</strong> · Medium</summary>

- **Description:** VMware VMX-attributed TCP payload with TLS metadata on 8443 reaches three distinct public IPs with one SNI within 90s; VM identity, allowlist status, encrypted content and C2 are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R883_VmwareVmxPublicTlsPeerFanoutRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R887 — IDE-attributed TLS tunnel-name traffic to two public peers</strong> · Medium</summary>

- **Description:** An IDE process sends TLS/443 payloads to two distinct public IPs under the same tunnel-like SNI within 45s; installation, extension behavior and tunneling are not proved.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R887_IdeProcessPublicTlsPeerPairRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R888 — ESXi management process TLS to two public peers</strong> · Medium</summary>

- **Description:** hostd- or vpxa-attributed TLS/443 data reaches two distinct public IPs with one SNI within 45s; management role, trust baseline and C2 are not established.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R888_EsxiManagementPublicTlsPeerPairRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R889 — ESXi management TLS/8443 repeated payload cadence</strong> · Medium</summary>

- **Description:** Four near-sized hostd/vpxa-attributed TLS/8443 data packets to one public peer spaced 5–20 seconds apart within 65s; neither junk payload encoding nor C2 is decoded.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R889_HostdVpxaTlsCadenceRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R890 — Rundll32-attributed TLS/9443 to two public peers</strong> · Medium</summary>

- **Description:** rundll32-attributed TLS/9443 payloads reach two distinct public IPs sharing one SNI within 45s; DLL loading, asymmetric traffic and malicious intent cannot be inferred.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R890_Rundll32PublicTlsPeerPairRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R893 — PowerShell-attributed DNS A query then matching SNI TLS</strong> · Medium</summary>

- **Description:** A PowerShell-attributed private DNS A query precedes TLS/443 from the same private source and process to a public peer with matching SNI within 60s; DNS response, asset role, allowlist and C2 are not proved.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R893_PowershellDnsQueryThenSniTlsRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R913 — Hostd public SSH-port data burst</strong> · Medium</summary>

- **Description:** Hostd/vpxa PID sends four TCP/22 data records of at least 512 bytes to a public peer. SSH content, encoding and C2 are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R913_HostdPublicSshDataBurstRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R920 — PowerShell public PS1 GET then TLS</strong> · Medium</summary>

- **Description:** Same private source and PowerShell PID sends public cleartext GET for .ps1 then public TLS/443 data. Download completion, IEX, execution and C2 are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R920_PowershellScriptGetThenPublicTlsRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R921 — AnyDesk public TCP/6568 SYN then same-peer TLS</strong> · Medium</summary>

- **Description:** Same private source, AnyDesk PID and public peer TCP/6568 SYN followed by TLS/443 data. Installation path, interactive control, consent and session outcome are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R921_AnydeskPublic6568ThenTlsRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R923 — IIS worker public ASPX HTTP POST</strong> · Medium</summary>

- **Description:** Local w3wp attribution and outbound public HTTP POST to an .aspx path with at least 512 transport bytes. IIS module installation, contents, persistence and C2 are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R923_IisWorkerPublicAspxPostRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R925 — BITSAdmin private SMB SYN then public HTTP GET</strong> · Medium</summary>

- **Description:** Same private source and bitsadmin PID TCP/445 SYN to private peer followed by public HTTP GET. BITS job, notification command, transfer and persistence are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R925_BitsadminPrivateSmbThenPublicHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R937 — IDE marketplace TLS then same-PID public SSH SYN</strong> · Medium</summary>

- **Description:** Code or JetBrains Toolbox PID sends TLS/443 with marketplace SNI then TCP/22 SYN to a public peer. Extension installation, SSH tunnel and authorization are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R937_IdeMacMarketplaceThenSshPublicSynRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R940 — TeamViewer public TLS/5938 vendor-name contact</strong> · Medium</summary>

- **Description:** TeamViewer-attributed public TLS/5938 with SNI equal to teamviewer.com or its subdomain. Remote control session, installation provenance, persistence and consent are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R940_TeamviewerPublic5938TlsRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R941 — Public proxy ingress then private SOCKS-port SYN</strong> · Medium</summary>

- **Description:** Public TCP/3128 SYN to a private host followed by that host initiating TCP/1080 SYN to another private peer within 45s. Proxy setup, forwarding configuration and actual relay are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R941_PublicProxySynThenPrivateSocksSynRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R954 — Public PHP GET then Bash public TCP/4444 SYN</strong> · Medium</summary>

- **Description:** Public HTTP GET for a .php path on a private host followed by Bash-attributed TCP/4444 SYN from that host to a public peer. Webshell creation, process ancestry, command execution and C2 are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R954_PublicPhpGetThenBashPublic4444SynRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R955 — Public ASPX POST then IIS worker public WinRM SYN</strong> · Medium</summary>

- **Description:** Public HTTP POST to a private .aspx endpoint followed by w3wp-attributed TCP/5985 SYN from that host to a public peer. File creation, child shells, authenticated WinRM, execution and compromise are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R955_PublicAspxPostThenW3wpPublicWinRmRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R963 — Public SSH ingress then sshd-attributed public TLS</strong> · Medium</summary>

- **Description:** Public SSH TCP/22 SYN to a private host then sshd-attributed public TLS/443 from that host. XZ backdoor, SSH child process, authentication and command execution are unknown.
- **Category:** CommandAndControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R963_PublicSshIngressThenSshdPublicTlsRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### CommandControl: 5 rules

<details>
<summary>Choose a rule from 5 CommandControl entries</summary>

<details>
<summary><strong>R835 — mshta HTA GET then rundll32 other-peer TLS payload</strong> · Medium</summary>

- **Description:** Same local IP two-process network sequence only; no payload execution, process ancestry, C2 command, or multi-stage implant inferred.
- **Category:** CommandControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R835_MshtaFetchThenRundll32TlsRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R837 — Conflicting public resolver A answers then selected-IP SYN</strong> · Medium</summary>

- **Description:** Two different public resolver IPs send different single public A answers for one qname to one client; that client SYNs to second answer within 60s. No resolver trust or poison proven.
- **Category:** CommandControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R837_ConflictingResolverAnswerThenSynRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R838 — Package client registry TLS then different-peer TLS</strong> · Medium</summary>

- **Description:** Same npm, pip or dotnet process and PID contacts a known package registry then a different public peer on TCP/8443; no package tampering or malicious build claimed.
- **Category:** CommandControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R838_PackageRegistryThenOtherPeerTlsRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R842 — Script-attributed public API TLS then reverse-tuple payload</strong> · Medium</summary>

- **Description:** PowerShell or wscript TLS request to a selected web-service SNI then reverse-5-tuple TCP reply within 60 seconds; no decrypted C2 content or commands inferred.
- **Category:** CommandControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R842_ScriptPublicApiTlsBidirectionalRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R844 — Three low-TTL single-IP DNS A answers changing over time</strong> · Medium</summary>

- **Description:** Same public DNS resolver sends three distinct single-public-IPv4 A answers with TTL 1-30s to one private client for one qname within 45s; not a fast-flux or C2 verdict.
- **Category:** CommandControl
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R844_LowTtlDnsAnswerChurnRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### ContainerDiscovery: 1 rules

<details>
<summary>Choose a rule from 1 ContainerDiscovery entries</summary>

<details>
<summary><strong>R821 — docker-attributed container-list then image-list HTTP API sequence</strong> · Medium</summary>

- **Description:** docker-attributed container-list then image-list HTTP API sequence. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** ContainerDiscovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R821_DockerContainerThenImageApiEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### ContainerExecution: 1 rules

<details>
<summary>Choose a rule from 1 ContainerExecution entries</summary>

<details>
<summary><strong>R822 — docker build API POST then same-process public TCP/443 SYN</strong> · Medium</summary>

- **Description:** docker build API POST then same-process public TCP/443 SYN. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** ContainerExecution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R822_DockerBuildPostThenExternalSynRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### DatabaseServiceExposure: 38 rules

<details>
<summary>Choose a rule from 38 DatabaseServiceExposure entries</summary>

<details>
<summary><strong>R433 — PostgreSQL External Login Attempt</strong> · High</summary>

- **Description:** Detects PostgreSQL External Login Attempt only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R433_PostgreSQLExternalLoginAttemptRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R434 — MySQL External Login Attempt</strong> · High</summary>

- **Description:** Detects MySQL External Login Attempt only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R434_MySQLExternalLoginAttemptRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R435 — MSSQL External Login Attempt</strong> · High</summary>

- **Description:** Detects MSSQL External Login Attempt only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R435_MSSQLExternalLoginAttemptRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R436 — MongoDB External Exposure Probe</strong> · High</summary>

- **Description:** Detects MongoDB External Exposure Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R436_MongoDBExternalExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R437 — Redis CONFIG SET Indicator</strong> · Critical</summary>

- **Description:** Detects Redis CONFIG SET Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R437_RedisCONFIGSETIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R438 — Redis Replication Abuse Indicator</strong> · Critical</summary>

- **Description:** Detects Redis Replication Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R438_RedisReplicationAbuseIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R439 — Memcached Stats Enumeration</strong> · Medium</summary>

- **Description:** Detects Memcached Stats Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R439_MemcachedStatsEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R440 — Elasticsearch Snapshot Repository Probe</strong> · High</summary>

- **Description:** Detects Elasticsearch Snapshot Repository Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R440_ElasticsearchSnapshotRepositoryProbeRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R441 — Cassandra CQL External Probe</strong> · High</summary>

- **Description:** Detects Cassandra CQL External Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R441_CassandraCQLExternalProbeRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R442 — Oracle TNS Enumeration</strong> · High</summary>

- **Description:** Detects Oracle TNS Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R442_OracleTNSEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R443 — CouchDB Admin Probe</strong> · High</summary>

- **Description:** Detects CouchDB Admin Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R443_CouchDBAdminProbeRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R444 — InfluxDB Query Endpoint Exposure</strong> · High</summary>

- **Description:** Detects InfluxDB Query Endpoint Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R444_InfluxDBQueryEndpointExposureRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R445 — ClickHouse HTTP SQL Probe</strong> · High</summary>

- **Description:** Detects ClickHouse HTTP SQL Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R445_ClickHouseHTTPSQLProbeRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R446 — Neo4j Browser Exposure Probe</strong> · High</summary>

- **Description:** Detects Neo4j Browser Exposure Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R446_Neo4jBrowserExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R447 — RabbitMQ Management Probe</strong> · High</summary>

- **Description:** Detects RabbitMQ Management Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R447_RabbitMQManagementProbeRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R448 — Kafka Broker External Access</strong> · High</summary>

- **Description:** Detects Kafka Broker External Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R448_KafkaBrokerExternalAccessRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R449 — Zookeeper Four Letter Word Probe</strong> · Medium</summary>

- **Description:** Detects Zookeeper Four Letter Word Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R449_ZookeeperFourLetterWordProbeRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R450 — NATS Broker External Access</strong> · High</summary>

- **Description:** Detects NATS Broker External Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R450_NATSBrokerExternalAccessRule.cs)
- **Detailed evidence and test scenarios:** [441-450](batches/RULE_BATCH_441-450.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R451 — MQTT Anonymous Login Pattern</strong> · High</summary>

- **Description:** Detects MQTT Anonymous Login Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R451_MQTTAnonymousLoginPatternRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R452 — Database Large Result Export Pattern</strong> · High</summary>

- **Description:** Detects Database Large Result Export Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R452_DatabaseLargeResultExportPatternRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R561 — Repeated Rejected Redis CONFIG SET Requests</strong> · Medium</summary>

- **Description:** Three distinct TCP connections from one public client to one private Redis endpoint yield correlated RESP2 errors within five minutes; no authentication or exploit outcome inferred.
- **Category:** DatabaseServiceExposure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R561_RedisConfigSetRejectedReplyBurstRule.cs)
- **Detailed evidence and test scenarios:** [561-561](batches/RULE_BATCH_561-561.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R562 — Redis CONFIG SET Error-to-OK Reply Transition</strong> · Medium</summary>

- **Description:** Two correlated RESP2 CONFIG SET errors on separate connections followed by a distinct +OK-shaped reply from the same private server to the same public client; authorization and server identity unknown.
- **Category:** DatabaseServiceExposure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R562_RedisConfigSetErrorToOkTransitionRule.cs)
- **Detailed evidence and test scenarios:** [562-562](batches/RULE_BATCH_562-562.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R564 — External Redis CONFIG SET OK Reply Across Private Subnets</strong> · High</summary>

- **Description:** One public IPv4 client receives independently correlated Redis CONFIG SET +OK-shaped replies from servers in two different private /24 networks within five minutes; server identity, authorization and persistent configuration changes remain unverified.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R564_ExternalRedisConfigSetOkSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [564-564](batches/RULE_BATCH_564-564.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R566 — Default HTTP Admin Attempt Then Redis CONFIG SET OK Reply</strong> · High</summary>

- **Description:** A public IPv4 peer sends a parser-confirmed default-Basic admin request to a private host and receives a separately correlated Redis CONFIG SET +OK-shaped reply from that same host within two minutes; neither HTTP login nor Redis configuration persistence is verified.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R566_DefaultBasicAdminThenRedisConfigOkRule.cs)
- **Detailed evidence and test scenarios:** [566-566](batches/RULE_BATCH_566-566.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R567 — Default HTTP Admin Attempt Then Redis CONFIG SET Denial</strong> · High</summary>

- **Description:** A public IPv4 peer sends a parser-confirmed default-Basic admin request to a private host and receives a separately correlated Redis CONFIG SET error-shaped reply from that same host within two minutes; neither HTTP login nor Redis authorization is verified.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R567_DefaultBasicAdminThenRedisConfigDeniedRule.cs)
- **Detailed evidence and test scenarios:** [567-567](batches/RULE_BATCH_567-567.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R568 — Redis CONFIG SET Denial Then Default HTTP Admin Attempt</strong> · High</summary>

- **Description:** A public IPv4 peer sends a wire-correlated Redis CONFIG SET error-shaped reply from a private host and subsequently sends a parser-confirmed default-Basic admin request to the same host within two minutes; neither HTTP login nor Redis authorization is verified.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R568_RedisConfigDeniedThenDefaultBasicAdminRule.cs)
- **Detailed evidence and test scenarios:** [568-568](batches/RULE_BATCH_568-568.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R571 — Redis CONFIG SET OK Reply Then Default HTTP Admin Attempt</strong> · High</summary>

- **Description:** A public IPv4 peer sends a wire-correlated Redis CONFIG SET OK-shaped reply from a private host and subsequently sends a parser-confirmed default-Basic admin request to the same host within two minutes; neither HTTP login nor Redis authorization is verified.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R571_RedisConfigOkThenDefaultBasicAdminRule.cs)
- **Detailed evidence and test scenarios:** [571-571](batches/RULE_BATCH_571-571.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R572 — Redis CONFIG SET Error Reply Then FTP Upload Command</strong> · High</summary>

- **Description:** Exact endpoint pair: Redis CONFIG SET Error reply before outbound FTP STOR/APPE command within 120 seconds.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R572_RedisErrorThenFtpUploadRule.cs)
- **Detailed evidence and test scenarios:** [572-572](batches/RULE_BATCH_572-572.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R573 — Redis CONFIG SET Ok Reply Then FTP Upload Command</strong> · High</summary>

- **Description:** Exact endpoint pair: Redis CONFIG SET Ok reply before outbound FTP STOR/APPE command within 120 seconds.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R573_RedisOkThenFtpUploadRule.cs)
- **Detailed evidence and test scenarios:** [573-573](batches/RULE_BATCH_573-573.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R574 — Redis CONFIG SET Error Reply After FTP Upload Command</strong> · High</summary>

- **Description:** Exact endpoint pair: Redis CONFIG SET Error reply after outbound FTP STOR/APPE command within 120 seconds.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R574_RedisErrorAfterFtpUploadRule.cs)
- **Detailed evidence and test scenarios:** [574-574](batches/RULE_BATCH_574-574.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R575 — Redis CONFIG SET Ok Reply After FTP Upload Command</strong> · High</summary>

- **Description:** Exact endpoint pair: Redis CONFIG SET Ok reply after outbound FTP STOR/APPE command within 120 seconds.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R575_RedisOkAfterFtpUploadRule.cs)
- **Detailed evidence and test scenarios:** [575-575](batches/RULE_BATCH_575-575.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R576 — Redis CONFIG SET Attempt Then FTP Upload Command</strong> · High</summary>

- **Description:** Public client issues parsed Redis CONFIG SET request to private server; same server subsequently sends FTP STOR/APPE to that client within 120 seconds, without claiming reply or transfer outcome.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R576_RedisConfigAttemptThenFtpUploadRule.cs)
- **Detailed evidence and test scenarios:** [576-576](batches/RULE_BATCH_576-576.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R577 — FTP Upload Command Then Redis CONFIG SET Attempt</strong> · High</summary>

- **Description:** Parsed outbound FTP upload command from private server to public peer followed by a Redis CONFIG SET request from that peer to the same private server within 120 seconds; outcomes unknown.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R577_FtpUploadThenRedisConfigAttemptRule.cs)
- **Detailed evidence and test scenarios:** [577-577](batches/RULE_BATCH_577-577.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R578 — Redis CONFIG SET Attempt Then Default HTTP Admin Attempt</strong> · High</summary>

- **Description:** Exact same public client sends a parsed Redis CONFIG SET request and known-default HTTP Basic admin request to the same private server in Redis-to-HTTP order within 120 seconds.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R578_RedisConfigAttemptThenDefaultBasicAdminRule.cs)
- **Detailed evidence and test scenarios:** [578-578](batches/RULE_BATCH_578-578.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R579 — Default HTTP Admin Attempt Then Redis CONFIG SET Attempt</strong> · High</summary>

- **Description:** Exact same public client sends a parsed Redis CONFIG SET request and known-default HTTP Basic admin request to the same private server in HTTP-to-Redis order within 120 seconds.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R579_DefaultBasicAdminThenRedisConfigAttemptRule.cs)
- **Detailed evidence and test scenarios:** [579-579](batches/RULE_BATCH_579-579.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R580 — External Redis CONFIG SET Request Subnet Fanout</strong> · High</summary>

- **Description:** One public client sends parser-observed RESP2 CONFIG SET requests to three distinct private /24 networks in five minutes; replies and outcome are unknown.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R580_ExternalRedisConfigRequestSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [580-584](batches/RULE_BATCH_580-584.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R581 — Outbound Redis CONFIG SET Request Subnet Fanout</strong> · High</summary>

- **Description:** One private client sends parsed Redis CONFIG SET requests to three distinct public /24 networks within five minutes; no server reply is required.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R581_OutboundRedisConfigRequestSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [580-584](batches/RULE_BATCH_580-584.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R585 — External Three-Service Administrative Request Probe</strong> · High</summary>

- **Description:** One public IPv4 peer issues classified default HTTP Basic admin, Redis CONFIG SET and SMB2 WRITE requests to the same private host within five minutes; no successful access is inferred.
- **Category:** DatabaseServiceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R585_ExternalThreeServiceAdministrativeProbeRule.cs)
- **Detailed evidence and test scenarios:** [585-585](batches/RULE_BATCH_585-585.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### DataLossStaging: 22 rules

<details>
<summary>Choose a rule from 22 DataLossStaging entries</summary>

<details>
<summary><strong>R493 — Browser Password Store File Upload</strong> · Critical</summary>

- **Description:** Detects Browser Password Store File Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R493_BrowserPasswordStoreFileUploadRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R494 — SSH Private Key Upload</strong> · Critical</summary>

- **Description:** Detects SSH Private Key Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R494_SSHPrivateKeyUploadRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R495 — KeePass Database Upload</strong> · Critical</summary>

- **Description:** Detects KeePass Database Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R495_KeePassDatabaseUploadRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R496 — VPN Config File Upload</strong> · High</summary>

- **Description:** Detects VPN Config File Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R496_VPNConfigFileUploadRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R497 — Browser Cookie Database Upload</strong> · Critical</summary>

- **Description:** Detects Browser Cookie Database Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R497_BrowserCookieDatabaseUploadRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R498 — Large Clipboard Sync Upload</strong> · Medium</summary>

- **Description:** Detects Large Clipboard Sync Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R498_LargeClipboardSyncUploadRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R499 — Remote Desktop File Transfer Burst</strong> · High</summary>

- **Description:** Detects Remote Desktop File Transfer Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R499_RemoteDesktopFileTransferBurstRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R500 — Compressed Archive Then Cloud Upload</strong> · High</summary>

- **Description:** Detects Compressed Archive Then Cloud Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R500_CompressedArchiveThenCloudUploadRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R501 — Multipart Form Data High Entropy Filename</strong> · High</summary>

- **Description:** Detects Multipart Form Data High Entropy Filename only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R501_MultipartFormDataHighEntropyFilenameRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R502 — Data URI Base64 POST Large</strong> · High</summary>

- **Description:** Detects Data URI Base64 POST Large only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R502_DataURIBase64POSTLargeRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R503 — Pastebin Raw POST Bulk</strong> · High</summary>

- **Description:** Detects Pastebin Raw POST Bulk only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R503_PastebinRawPOSTBulkRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R504 — GitHub Gist Secret Post</strong> · Critical</summary>

- **Description:** Detects GitHub Gist Secret Post only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R504_GitHubGistSecretPostRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R505 — Discord Attachment Upload Burst</strong> · High</summary>

- **Description:** Detects Discord Attachment Upload Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R505_DiscordAttachmentUploadBurstRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R506 — Telegram Document Exfil Burst</strong> · High</summary>

- **Description:** Detects Telegram Document Exfil Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R506_TelegramDocumentExfilBurstRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R507 — Mega NZ Upload Pattern</strong> · High</summary>

- **Description:** Detects Mega NZ Upload Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R507_MegaNZUploadPatternRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R508 — Rclone UserAgent Egress</strong> · High</summary>

- **Description:** Detects Rclone UserAgent Egress only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R508_RcloneUserAgentEgressRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R509 — Rsync External Push</strong> · High</summary>

- **Description:** Detects Rsync External Push only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R509_RsyncExternalPushRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R510 — S3 Compatible Unknown Endpoint Upload</strong> · High</summary>

- **Description:** Detects S3 Compatible Unknown Endpoint Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R510_S3CompatibleUnknownEndpointUploadRule.cs)
- **Detailed evidence and test scenarios:** [501-510](batches/RULE_BATCH_501-510.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R511 — DB Client Export Then HTTP Upload</strong> · Critical</summary>

- **Description:** Detects DB Client Export Then HTTP Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R511_DBClientExportThenHTTPUploadRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R512 — Sensitive Filename To Personal Email</strong> · Critical</summary>

- **Description:** Detects Sensitive Filename To Personal Email only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DataLossStaging
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R512_SensitiveFilenameToPersonalEmailRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R657 — Script or CLI process posting to paste-service API</strong> · Medium</summary>

- **Description:** Script or CLI process posting to paste-service API. R220 and R503 count large or repeated paste-service POSTs. This candidate requires an exact API route and locally attributed scripting client for one request.
- **Category:** DataLossStaging
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R657_ScriptAttributedPasteApiHttpPostRequestRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R733 — macOS utility or Office process TLS contact to text-storage service</strong> · Low</summary>

- **Description:** osascript, curl, wget, Microsoft Word, or Microsoft Excel is associated with outbound TLS/443 to a known text-storage service. Clipboard/file reads, HTTP method/body, authentication, upload, exfiltration and service response are not observed.
- **Category:** DataLossStaging
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R733_MacProcessTextStorageTlsContactRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### DefenseEvasion: 1 rules

<details>
<summary>Choose a rule from 1 DefenseEvasion entries</summary>

<details>
<summary><strong>R843 — Same process and peer TLS 1.3 then TLS 1.0 or 1.1</strong> · Medium</summary>

- **Description:** Same local curl/python2 process and public peer observed with TLS 1.3 then older TLS 1.0/1.1 within 90 seconds; no negotiated downgrade or exploit confirmed.
- **Category:** DefenseEvasion
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R843_ProcessPeerTlsVersionRegressionRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Detection-engine health: 7 rules

<details>
<summary>Choose a rule from 7 Detection-engine health entries</summary>

<details>
<summary><strong>R050 — Rule Execution Gap</strong> · Medium</summary>

- **Description:** Rule evaluation has stopped or exceeded the allowed gap.
- **Category:** Detection-engine health
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Health/R050_RuleExecutionGapRule.cs)
- **Detailed evidence and test scenarios:** [046-050](batches/RULE_BATCH_046-050.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R051 — Packet Capture Drop Surge</strong> · Medium</summary>

- **Description:** Packet capture drop counter increased above threshold.
- **Category:** Detection-engine health
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Health/R051_PacketCaptureDropSurgeRule.cs)
- **Detailed evidence and test scenarios:** [051-055](batches/RULE_BATCH_051-055.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R052 — Sink Queue Backpressure</strong> · Medium</summary>

- **Description:** Sink delivery queue is blocked or backpressured.
- **Category:** Detection-engine health
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Health/R052_SinkQueueBackpressureRule.cs)
- **Detailed evidence and test scenarios:** [051-055](batches/RULE_BATCH_051-055.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R053 — Detection Journal Write Failure</strong> · Medium</summary>

- **Description:** Mandatory detection journal failed to persist events.
- **Category:** Detection-engine health
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Health/R053_DetectionJournalWriteFailureRule.cs)
- **Detailed evidence and test scenarios:** [051-055](batches/RULE_BATCH_051-055.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R054 — Rule Config Reload Failure</strong> · Medium</summary>

- **Description:** Rule configuration reload failed; previous config remains active.
- **Category:** Detection-engine health
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Health/R054_RuleConfigReloadFailureRule.cs)
- **Detailed evidence and test scenarios:** [051-055](batches/RULE_BATCH_051-055.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R055 — Threat Feed Stale</strong> · Medium</summary>

- **Description:** Threat feed has not been refreshed within the configured interval.
- **Category:** Detection-engine health
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Health/R055_ThreatFeedStaleRule.cs)
- **Detailed evidence and test scenarios:** [051-055](batches/RULE_BATCH_051-055.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R056 — Time Skew / Clock Jump</strong> · Medium</summary>

- **Description:** Local clock skew or jump exceeded threshold.
- **Category:** Detection-engine health
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Health/R056_TimeSkewClockJumpRule.cs)
- **Detailed evidence and test scenarios:** [056-060](batches/RULE_BATCH_056-060.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### DevOpsSupplyChain: 20 rules

<details>
<summary>Choose a rule from 20 DevOpsSupplyChain entries</summary>

<details>
<summary><strong>R353 — GitHub Personal Access Token In Traffic</strong> · Critical</summary>

- **Description:** Detects GitHub Personal Access Token In Traffic only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R353_GitHubPersonalAccessTokenInTrafficRule.cs)
- **Detailed evidence and test scenarios:** [351-355](batches/RULE_BATCH_351-355.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R354 — GitLab Private Token In Traffic</strong> · Critical</summary>

- **Description:** Detects GitLab Private Token In Traffic only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R354_GitLabPrivateTokenInTrafficRule.cs)
- **Detailed evidence and test scenarios:** [351-355](batches/RULE_BATCH_351-355.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R355 — Jenkins Script Console Probe</strong> · High</summary>

- **Description:** Detects Jenkins Script Console Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R355_JenkinsScriptConsoleProbeRule.cs)
- **Detailed evidence and test scenarios:** [351-355](batches/RULE_BATCH_351-355.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R356 — Jenkins Crumb Issuer Enumeration</strong> · Medium</summary>

- **Description:** Detects Jenkins Crumb Issuer Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R356_JenkinsCrumbIssuerEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [356-360](batches/RULE_BATCH_356-360.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R357 — TeamCity Auth Bypass Probe</strong> · High</summary>

- **Description:** Detects TeamCity Auth Bypass Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R357_TeamCityAuthBypassProbeRule.cs)
- **Detailed evidence and test scenarios:** [356-360](batches/RULE_BATCH_356-360.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R358 — Bamboo Build Artifact Bulk Download</strong> · Medium</summary>

- **Description:** Detects Bamboo Build Artifact Bulk Download only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R358_BambooBuildArtifactBulkDownloadRule.cs)
- **Detailed evidence and test scenarios:** [356-360](batches/RULE_BATCH_356-360.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R359 — Azure DevOps PAT In URL</strong> · Critical</summary>

- **Description:** Detects Azure DevOps PAT In URL only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R359_AzureDevOpsPATInURLRule.cs)
- **Detailed evidence and test scenarios:** [356-360](batches/RULE_BATCH_356-360.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R360 — CircleCI API Token Exposure</strong> · High</summary>

- **Description:** Detects CircleCI API Token Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R360_CircleCIAPITokenExposureRule.cs)
- **Detailed evidence and test scenarios:** [356-360](batches/RULE_BATCH_356-360.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R361 — GitHub Actions OIDC Token Request</strong> · High</summary>

- **Description:** Detects GitHub Actions OIDC Token Request only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R361_GitHubActionsOIDCTokenRequestRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R362 — GitHub Actions Runner Registration Token</strong> · High</summary>

- **Description:** Detects GitHub Actions Runner Registration Token only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R362_GitHubActionsRunnerRegistrationTokenRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R363 — CI Artifact Archive Download Burst</strong> · High</summary>

- **Description:** Detects CI Artifact Archive Download Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R363_CIArtifactArchiveDownloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R364 — Secrets Manager API Enumeration</strong> · High</summary>

- **Description:** Detects Secrets Manager API Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R364_SecretsManagerAPIEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R365 — HashiCorp Vault Token In HTTP</strong> · Critical</summary>

- **Description:** Detects HashiCorp Vault Token In HTTP only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R365_HashiCorpVaultTokenInHTTPRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R366 — Vault Transit Decrypt Burst</strong> · High</summary>

- **Description:** Detects Vault Transit Decrypt Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R366_VaultTransitDecryptBurstRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R367 — Terraform Cloud Token Exposure</strong> · High</summary>

- **Description:** Detects Terraform Cloud Token Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R367_TerraformCloudTokenExposureRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R368 — Docker Hub Pull Storm</strong> · Medium</summary>

- **Description:** Detects Docker Hub Pull Storm only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R368_DockerHubPullStormRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R369 — NPM Token Exposure</strong> · Critical</summary>

- **Description:** Detects NPM Token Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R369_NPMTokenExposureRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R370 — PyPI Credential Upload Attempt</strong> · High</summary>

- **Description:** Detects PyPI Credential Upload Attempt only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R370_PyPICredentialUploadAttemptRule.cs)
- **Detailed evidence and test scenarios:** [361-370](batches/RULE_BATCH_361-370.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R371 — Maven Repository Credential Use</strong> · High</summary>

- **Description:** Detects Maven Repository Credential Use only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R371_MavenRepositoryCredentialUseRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R372 — Dependency Confusion Package Name Pattern</strong> · Medium</summary>

- **Description:** Detects Dependency Confusion Package Name Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** DevOpsSupplyChain
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R372_DependencyConfusionPackageNamePatternRule.cs)
- **Detailed evidence and test scenarios:** [371-380](batches/RULE_BATCH_371-380.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Discovery: 16 rules

<details>
<summary>Choose a rule from 16 Discovery entries</summary>

<details>
<summary><strong>R773 — Private-source SNMP target fanout</strong> · Low</summary>

- **Description:** One private source sends coherent UDP/161 observations to four distinct private targets within thirty seconds. System-information OIDs, source authorization, device role, SNMP response content and successful discovery are not observed.
- **Category:** Discovery
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R773_PrivateSnmpTargetFanoutDiscoveryRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R788 — Named resolver repeats TXT question to three public upstreams</strong> · Medium</summary>

- **Description:** Named resolver repeats TXT question to three public upstreams. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R788_DnsResolverMultiUpstreamTxtQueryRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R797 — wmic-attributed RPC SYN to four internal hosts in one subnet</strong> · Medium</summary>

- **Description:** wmic-attributed RPC SYN to four internal hosts in one subnet. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R797_WmicRpcPrivateTargetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R804 — private SNMP probe followed by SSH SYN to same private device</strong> · Medium</summary>

- **Description:** private SNMP probe followed by SSH SYN to same private device. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R804_SnmpProbeThenSshSynRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R864 — Docker-proxy public TCP/1080 SYN peer fanout</strong> · Medium</summary>

- **Description:** Docker-proxy-attributed TCP/1080 SYN attempts reach three distinct public IPs within 60s; proxy deployment, container identity and abuse are unknown.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R864_DockerProxyPublicSocksSynFanoutRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R871 — Private Modbus TCP payloads across four devices</strong> · Medium</summary>

- **Description:** A modpoll-attributed private client sends similarly sized TCP data to four distinct private TCP/502 hosts in one /24 within 60s; read function, asset identity and collection outcome are unknown.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R871_ModbusMultiDevicePayloadWalkRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R872 — Public client probes two embedded camera image endpoints</strong> · Medium</summary>

- **Description:** One public client requests both /snapshot.jpg and /stream.mjpg on the same private HTTP service within 45s; no image capture, device type or screenshot return verified.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R872_EmbeddedSnapshotEndpointPairRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R873 — SSDP-port multicast then private HTTP device SYN</strong> · Medium</summary>

- **Description:** Private source sends UDP/1900 to SSDP multicast then TCP SYN to another private device&#x27;s 8008 within 60s; no decoded M-SEARCH, IGMP join or discovered service verified.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R873_SsdpMulticastThenDeviceHttpSynRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R894 — Public source probes SSH then web API login</strong> · Medium</summary>

- **Description:** Same public client SYNs to private SSH/22 then POSTs /api/login on the same private host HTTP/80 within 60s; neither authentication, server operating system, exposed ICS role nor authorization is established.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R894_PublicSshThenWebApiProbeRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R895 — Private client SYNs to Modbus and EtherNet/IP host ports</strong> · Medium</summary>

- **Description:** Same private source SYNs to TCP/502 then TCP/44818 on one private host within 45s; newly attached device, inventory enrollment, OT asset role and authentication are unknown.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R895_PrivateIndustrialDualPortSynRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R898 — Net-attributed private SMB SYN peer fanout</strong> · Medium</summary>

- **Description:** Same private source and net/net1 PID SYNs to three distinct private TCP/445 peers in 45 seconds; share enumeration, SMB authentication and lateral success are unknown.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R898_NetPrivateSmbSynPeerFanoutRule.cs)
- **Detailed evidence and test scenarios:** [896-900](batches/RULE_BATCH_896-900.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R901 — Nltest private LDAP then Global Catalog SYN</strong> · Medium</summary>

- **Description:** Same private source, nltest PID and private peer receive TCP/389 then TCP/3268 SYNs within 45s; LDAP queries, domain trust enumeration and authentication are not observed.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R901_NltestLdapThenGlobalCatalogSynRule.cs)
- **Detailed evidence and test scenarios:** [901-905](batches/RULE_BATCH_901-905.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R956 — Net utility private RPC then same-peer LDAP SYN</strong> · Medium</summary>

- **Description:** Same net/net1 PID sends TCP/135 then TCP/389 SYN to one private peer. Enumeration command, returned system/user data and authorization are unknown.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R956_NetPrivateRpcThenLdapRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R957 — WMIC private RPC then same-peer SMB SYN</strong> · Medium</summary>

- **Description:** Same WMIC PID sends private TCP/135 then TCP/445 SYN to one peer. WMI query, returned system information, authenticated session, OT role and authorization are unknown.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R957_WmicPrivateRpcThenSmbRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R958 — Curl connectivity-check GET then private TCP/902 SYN</strong> · Medium</summary>

- **Description:** Same curl PID sends public HTTP GET to exact connectivitycheck.gstatic.com /generate_204 followed by private TCP/902 SYN. ESXi identity, shell command, service identity and authorized connectivity check are unknown.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R958_CurlConnectivityGetThenPrivate902SynRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R959 — PowerShell public DNS-port SYN then same-peer TLS</strong> · Medium</summary>

- **Description:** Same PowerShell PID contacts public TCP/53 then sends TLS/443 data to the same public peer. Test-NetConnection, DNS query, connectivity test intent and authorization are unknown.
- **Category:** Discovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R959_PowershellPublicDnsPortSynThenTlsRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### DNS: 7 rules

<details>
<summary>Choose a rule from 7 DNS entries</summary>

<details>
<summary><strong>R006 — DNS Anomalies</strong> · Medium</summary>

- **Description:** DNS anomaly detected
- **Category:** DNS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R006_DnsAnomaliesRule.cs)
- **Detailed evidence and test scenarios:** [006-010](batches/RULE_BATCH_006-010.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R022 — DNS NXDOMAIN Spike</strong> · Medium</summary>

- **Description:** NXDOMAIN spike detected
- **Category:** DNS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R022_DnsNxdomainSpikeRule.cs)
- **Detailed evidence and test scenarios:** [021-025](batches/RULE_BATCH_021-025.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R028 — Direct External DNS</strong> · Medium</summary>

- **Description:** Direct external DNS resolver usage
- **Category:** DNS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R028_DirectExternalDnsRule.cs)
- **Detailed evidence and test scenarios:** [026-030](batches/RULE_BATCH_026-030.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R031 — DNS TXT Spike</strong> · Medium</summary>

- **Description:** DNS TXT query spike
- **Category:** DNS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R031_DnsTxtSpikeRule.cs)
- **Detailed evidence and test scenarios:** [031-035](batches/RULE_BATCH_031-035.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R034 — DNS-over-HTTPS Heuristic</strong> · Medium</summary>

- **Description:** DNS-over-HTTPS heuristic
- **Category:** DNS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R034_DnsOverHttpsHeuristicRule.cs)
- **Detailed evidence and test scenarios:** [031-035](batches/RULE_BATCH_031-035.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R038 — Encrypted DNS Bootstrap</strong> · Medium</summary>

- **Description:** Encrypted DNS bootstrap behavior
- **Category:** DNS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R038_EncryptedDnsBootstrapRule.cs)
- **Detailed evidence and test scenarios:** [036-040](batches/RULE_BATCH_036-040.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R048 — Alternate DoH Patterns</strong> · Medium</summary>

- **Description:** Alternate DNS-over-HTTPS pattern
- **Category:** DNS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R048_AlternateDohPatternsRule.cs)
- **Detailed evidence and test scenarios:** [046-050](batches/RULE_BATCH_046-050.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Dns: 14 rules

<details>
<summary>Choose a rule from 14 Dns entries</summary>

<details>
<summary><strong>R094 — DGA-Like Domain Query</strong> · High</summary>

- **Description:** Flags DNS questions whose second-level domain shape looks algorithmically generated based on label entropy, vowel scarcity, digit mix, and DNS field evidence.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R094_DGALikeDomainQueryRule.cs)
- **Detailed evidence and test scenarios:** [091-095](batches/RULE_BATCH_091-095.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R095 — Newly Observed Domain With High Entropy</strong> · High</summary>

- **Description:** Flags first-seen DNS domains whose full query name is unusually long and high-entropy, using baseline observations rather than free-text matching.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R095_NewlyObservedDomainWithHighEntropyRule.cs)
- **Detailed evidence and test scenarios:** [091-095](batches/RULE_BATCH_091-095.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R096 — Fast-Flux DNS Pattern</strong> · High</summary>

- **Description:** Flags DNS responses that return many distinct IP address answers with unusually low TTL values, consistent with fast-flux-style rotation rather than host text matching.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R096_FastFluxDNSPatternRule.cs)
- **Detailed evidence and test scenarios:** [096-100](batches/RULE_BATCH_096-100.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R097 — Excessive Unique Subdomains</strong> · High</summary>

- **Description:** Detects many distinct subdomains for the same root from one source within a time window, using DNS qname structure rather than text-only indicators.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R097_ExcessiveUniqueSubdomainsRule.cs)
- **Detailed evidence and test scenarios:** [096-100](batches/RULE_BATCH_096-100.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R098 — Suspicious Dynamic DNS Provider</strong> · High</summary>

- **Description:** Flags DNS questions for dynamic-DNS provider domains when the queried label is first-seen or sufficiently random-looking, using the DNS qname as primary evidence.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R098_SuspiciousDynamicDNSProviderRule.cs)
- **Detailed evidence and test scenarios:** [096-100](batches/RULE_BATCH_096-100.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R099 — DNS Query to Newly Registered Domain</strong> · High</summary>

- **Description:** Flags DNS questions with recent reputation observation timing and DNS evidence; registration age is not available from this record.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R099_DNSQueryToNewlyRegisteredDomainRule.cs)
- **Detailed evidence and test scenarios:** [096-100](batches/RULE_BATCH_096-100.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R100 — DNS Query for Internal Name to External Resolver</strong> · High</summary>

- **Description:** Detects repeated DNS questions for internal-only names sent to a public resolver, using actual DNS qname and resolver telemetry rather than generic host text.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R100_DNSQueryForInternalNameToExternalResolverRule.cs)
- **Detailed evidence and test scenarios:** [096-100](batches/RULE_BATCH_096-100.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R101 — DNS CNAME Chain Abuse</strong> · High</summary>

- **Description:** Flags unusually deep DNS CNAME chains in actual response telemetry, while suppressing common CDN-style aliasing unless the chain depth is excessive.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R101_DNSCNAMEChainAbuseRule.cs)
- **Detailed evidence and test scenarios:** [101-105](batches/RULE_BATCH_101-105.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R102 — DNS Tunneling via Long Labels</strong> · High</summary>

- **Description:** Flags suspiciously long or repeated high-entropy DNS labels in structured DNS telemetry, while excluding common validation and mail-authentication records.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R102_DNSTunnelingViaLongLabelsRule.cs)
- **Detailed evidence and test scenarios:** [101-105](batches/RULE_BATCH_101-105.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R103 — DNS Beaconing With Stable Interval</strong> · High</summary>

- **Description:** Detects repeated DNS questions to the same root with low-jitter intervals, using windowed cadence analysis over structured DNS telemetry.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Dns/R103_DNSBeaconingWithStableIntervalRule.cs)
- **Detailed evidence and test scenarios:** [101-105](batches/RULE_BATCH_101-105.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R763 — ESXi-style DNS tool high-entropy query burst</strong> · Medium</summary>

- **Description:** busybox or nslookup is associated with three high-entropy DNS queries to a public resolver for the same root domain within two minutes. ESXi asset identity, shell script origin, malicious VIB presence, encoded payload meaning and DNS tunneling success are not observed.
- **Category:** Dns
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R763_EsxiStyleDnsTunnelShapeRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R764 — Linux DNS-tunneling tool high-entropy query burst</strong> · High</summary>

- **Description:** iodine, iodined, dnscat2, dnscat2-client, or dig is associated with three high-entropy DNS queries to a public resolver for the same root domain within two minutes. Cron/reverse-shell ancestry, encoded content, authoritative-server control and tunneling success are not observed.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R764_LinuxDnsTunnelToolQueryBurstRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R766 — osascript high-entropy DNS query burst</strong> · Medium</summary>

- **Description:** osascript is associated with three high-entropy DNS queries to a public resolver for the same root domain within two minutes. AppleScript origin, encoded content, authoritative-server control, data exfiltration and command-and-control are not established.
- **Category:** Dns
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R766_OsascriptHighEntropyDnsQueryBurstRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R767 — Windows script/LOLBIN high-entropy DNS query burst</strong> · High</summary>

- **Description:** PowerShell, rundll32, or Windows Python is associated with three high-entropy DNS queries to a public resolver for the same root domain within two minutes. Command line, encoded payload meaning, authoritative-server ownership and DNS-tunneling success are not observed.
- **Category:** Dns
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R767_WindowsScriptHighEntropyDnsQueryBurstRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### DnsAdvanced: 35 rules

<details>
<summary>Choose a rule from 35 DnsAdvanced entries</summary>

<details>
<summary><strong>R178 — DNS Query For Crypto Mining Pool</strong> · High</summary>

- **Description:** Detects DNS questions to known mining pool infrastructure when the queried name carries pool-like semantics, rather than matching any cryptocurrency-related hostname text.
- **Category:** DnsAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R178_DnsQueryForCryptoMiningPoolRule.cs)
- **Detailed evidence and test scenarios:** [176-180](batches/RULE_BATCH_176-180.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R179 — DNS Query For Tor Onion Gateway</strong> · Medium</summary>

- **Description:** Detects DNS queries that target Tor onion gateway services or literal onion-style names instead of any occurrence of the word onion.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R179_DnsQueryForTorOnionGatewayRule.cs)
- **Detailed evidence and test scenarios:** [176-180](batches/RULE_BATCH_176-180.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R180 — DNS Query To High-Risk TLD</strong> · Low</summary>

- **Description:** Detects first-seen or unusually shaped DNS queries under historically risky TLDs instead of alerting on every domain under those TLDs.
- **Category:** DnsAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R180_DnsQueryToHighRiskTldRule.cs)
- **Detailed evidence and test scenarios:** [176-180](batches/RULE_BATCH_176-180.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R181 — Excessive DNS ANY Queries</strong> · Medium</summary>

- **Description:** Detects repeated structured DNS ANY queries from the same source instead of a single ANY query or generic text match.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R181_ExcessiveDnsAnyQueriesRule.cs)
- **Detailed evidence and test scenarios:** [181-185](batches/RULE_BATCH_181-185.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R182 — DNS Zone Transfer Attempt</strong> · High</summary>

- **Description:** Detects structured AXFR or IXFR attempts that cross an internal/external boundary or target public-facing DNS infrastructure, rather than any text containing AXFR.
- **Category:** DnsAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R182_DnsZoneTransferAttemptRule.cs)
- **Detailed evidence and test scenarios:** [181-185](batches/RULE_BATCH_181-185.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R183 — DNSSEC Random Subdomain Spike</strong> · Medium</summary>

- **Description:** Detects bursts of distinct DNSSEC-focused queries for random-looking subdomains instead of ordinary apex DNSSEC validation.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R183_DnssecRandomSubdomainSpikeRule.cs)
- **Detailed evidence and test scenarios:** [181-185](batches/RULE_BATCH_181-185.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R184 — External Reverse DNS Enumeration</strong> · Medium</summary>

- **Description:** Detects repeated reverse-DNS lookups sent to external resolvers instead of isolated PTR traffic.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R184_ExternalReverseDnsEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [181-185](batches/RULE_BATCH_181-185.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R185 — Canary Or Metadata Domain Probe</strong> · Low</summary>

- **Description:** Detects structured DNS queries to out-of-band canary or cloud metadata domains instead of generic collaborator text matches.
- **Category:** DnsAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R185_CanaryOrMetadataDomainProbeRule.cs)
- **Detailed evidence and test scenarios:** [181-185](batches/RULE_BATCH_181-185.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R186 — DNS CAA Record Probing Burst</strong> · Low</summary>

- **Description:** Detects bursts of CAA lookups across many distinct roots instead of isolated certificate-validation style queries.
- **Category:** DnsAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R186_DnsCaaRecordProbingBurstRule.cs)
- **Detailed evidence and test scenarios:** [186-190](batches/RULE_BATCH_186-190.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R187 — DNS NULL Query Usage</strong> · Medium</summary>

- **Description:** Detects structured DNS NULL queries, which are rare in normal environments and should not rely on generic text hints.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R187_DnsNullQueryUsageRule.cs)
- **Detailed evidence and test scenarios:** [186-190](batches/RULE_BATCH_186-190.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R188 — Active Directory SRV Enumeration</strong> · Medium</summary>

- **Description:** Detects short-window bursts of distinct AD SRV queries rather than single routine AD service discovery lookups.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R188_ActiveDirectorySrvEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [186-190](batches/RULE_BATCH_186-190.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R189 — AD SRV Query To External Resolver</strong> · High</summary>

- **Description:** Detects Active Directory SRV lookups sent to external resolvers, focusing on internal namespace leakage rather than ordinary public SRV traffic.
- **Category:** DnsAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R189_AdSrvQueryToExternalResolverRule.cs)
- **Detailed evidence and test scenarios:** [186-190](batches/RULE_BATCH_186-190.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R190 — DNS Short TTL Burst</strong> · Medium</summary>

- **Description:** Detects bursts of very low-TTL DNS responses for non-approved roots instead of single short-TTL answers that can occur legitimately.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R190_DnsShortTtlBurstRule.cs)
- **Detailed evidence and test scenarios:** [186-190](batches/RULE_BATCH_186-190.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R191 — Consonant-Heavy DGA Domain</strong> · Medium</summary>

- **Description:** Detects consonant-heavy, entropy-rich structured DNS names that resemble algorithmic generation rather than human-readable domains.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R191_ConsonantHeavyDgaDomainRule.cs)
- **Detailed evidence and test scenarios:** [191-195](batches/RULE_BATCH_191-195.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R192 — Punycode Homograph Domain</strong> · Medium</summary>

- **Description:** Detects first-seen punycode labels under common ASCII TLDs that are more likely to support homograph abuse than legitimate IDN ccTLD usage.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R192_PunycodeHomographDomainRule.cs)
- **Detailed evidence and test scenarios:** [191-195](batches/RULE_BATCH_191-195.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R193 — Cloud Brand Lookalike Domain</strong> · Medium</summary>

- **Description:** Detects newly observed DNS names with explicit brand-lookalike labels for common cloud and identity vendors instead of broad substring matching.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R193_CloudBrandLookalikeDomainRule.cs)
- **Detailed evidence and test scenarios:** [191-195](batches/RULE_BATCH_191-195.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R194 — DoH Over Uncommon Host</strong> · Medium</summary>

- **Description:** Detects DNS-over-HTTPS semantics on external hosts that are not approved public resolvers, instead of matching any dns-query path.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R194_DohOverUncommonHostRule.cs)
- **Detailed evidence and test scenarios:** [191-195](batches/RULE_BATCH_191-195.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R195 — DNS Over TLS To Unapproved Resolver</strong> · High</summary>

- **Description:** Detects external DNS-over-TLS sessions on port 853 when the resolver host is not approved, instead of relying on port-only heuristics.
- **Category:** DnsAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R195_DnsOverTlsToUnapprovedResolverRule.cs)
- **Detailed evidence and test scenarios:** [191-195](batches/RULE_BATCH_191-195.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R196 — NXDOMAIN Unique Root Spike</strong> · Medium</summary>

- **Description:** Detects sources that trigger many distinct NXDOMAIN roots in a short window instead of isolated typos or single-root misses.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R196_NxdomainUniqueRootSpikeRule.cs)
- **Detailed evidence and test scenarios:** [196-200](batches/RULE_BATCH_196-200.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R197 — DNS Rebinding Private IP Answer</strong> · High</summary>

- **Description:** Detects public-looking DNS responses that resolve to private or loopback IP space under rebinding-favored conditions, instead of flagging every split-horizon answer.
- **Category:** DnsAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R197_DnsRebindingPrivateIpAnswerRule.cs)
- **Detailed evidence and test scenarios:** [196-200](batches/RULE_BATCH_196-200.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R612 — External OAST callback DNS query</strong> · Medium</summary>

- **Description:** Parser-backed DNS query shape only; outcome unknown.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R612_ExternalOastCallbackDnsQueryRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R613 — Cobalt Strike-like staging label DNS query</strong> · Medium</summary>

- **Description:** Parser-backed DNS query shape only; outcome unknown.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R613_CobaltStrikeLikeDnsStagingLabelRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R614 — Historical DPRK-associated DNS domain query</strong> · Medium</summary>

- **Description:** Parser-backed DNS query shape only; outcome unknown.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R614_HistoricalDprkDomainDnsQueryRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R615 — Anonfiles file-sharing domain DNS query</strong> · Medium</summary>

- **Description:** Parser-backed DNS query shape only; outcome unknown.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R615_AnonfilesDomainDnsQueryRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R620 — LocaltoNet Service DNS Query</strong> · Medium</summary>

- **Description:** DNS query: specific workbook candidate, detection only; Sigma originally requires an initiated process connection. This narrower DNS-only variant cannot attribute a process or an established tunnel.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R620_LocaltoNetServiceDnsQueryRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R621 — Historical 3CX-associated Domain DNS Query</strong> · Medium</summary>

- **Description:** DNS query: specific workbook candidate, detection only; Sigma requires association with 3CXDesktopApp.exe; a DNS QNAME cannot establish process or malware, and historical domains may be stale.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R621_HistoricalThreeCxDomainDnsQueryRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R629 — Hybrid Connection Manager DNS lookup to Azure Service Bus</strong> · Low</summary>

- **Description:** Original R2475; R620 LocaltoNet domain alone; here an exact local process + DNS query conjunction, benign Azure connector likely. Only observable packet fields, no asserted outcome.
- **Category:** DnsAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R629_HybridConnectionManagerServiceBusDnsRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R637 — Historical GALLIUM-associated DNS indicator query</strong> · Low</summary>

- **Description:** Historical GALLIUM-associated DNS indicator query. Observed evidence only; Historical 2019 research, stale domains and possible reuse; DNS query is not evidence of actor attribution.
- **Category:** DnsAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R637_HistoricalGalliumDnsIndicatorQueryRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R641 — Office process-associated high-entropy DNS query</strong> · Medium</summary>

- **Description:** Office process-associated high-entropy DNS query. Observed evidence only; Best-effort process association and domain entropy cannot establish a DGA or process execution; Office telemetry may be absent.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R641_OfficeProcessHighEntropyDnsQueryRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R660 — OT engineering process sends native DNS query directly to public resolver</strong> · Low</summary>

- **Description:** OT engineering process sends native DNS query directly to public resolver. R102 is DNS label tunneling; this rule requires attributed engineering process and a public resolver, without claiming DNS policy violation.
- **Category:** DnsAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R660_EngineeringProcessDirectPublicDnsQueryRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R723 — Script process direct external high-entropy DNS query</strong> · Medium</summary>

- **Description:** A script/interpreter process is associated with a direct query to a public DNS destination where the first label is long and high-diversity. Resolver policy, tunneling semantics, payload encoding, C2, and process command line are not observed.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R723_ScriptProcessDirectExternalHighEntropyDnsRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R727 — Linux script process direct external DNS-over-TLS contact</strong> · Medium</summary>

- **Description:** A scripting or shell process is associated with direct outbound TLS/853 to a public peer. Resolver policy, asset role, DNS payload, DoT authorization, tunneling, C2 and query contents are not observed.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R727_LinuxScriptProcessDirectExternalDotRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R834 — script-host distinct DGA-like DNS burst followed by TLS payload</strong> · Medium</summary>

- **Description:** Four script-attributed high-digit DNS questions and a subsequent TLS payload at a public peer; no DGA attribution, NXDOMAIN ratio or malicious verdict is established.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R834_DgaLikeDnsBurstThenScriptTlsRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R899 — VMware management-process TLS to public resolver SNI</strong> · Medium</summary>

- **Description:** Local hostd/vpxa attribution and TLS/443 to a public IP with exact recognized resolver SNI; HTTPS DNS requests, resolver identity, VMware asset role and tunneling are unknown.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R899_VmwarePublicResolverTlsSniRule.cs)
- **Detailed evidence and test scenarios:** [896-900](batches/RULE_BATCH_896-900.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R916 — Hostd public DNS query then reverse-tuple NXDOMAIN</strong> · Medium</summary>

- **Description:** Hostd/vpxa capture-attested UDP IN/A query to a public resolver followed by a validated no-answer NXDOMAIN with matching transaction ID, normalized question and reverse tuple. DGA, resolver trust and attack outcome remain unknown.
- **Category:** DnsAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R916_HostdPublicDnsQueryNxdomainReplyRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### DnsThreat: 5 rules

<details>
<summary>Choose a rule from 5 DnsThreat entries</summary>

<details>
<summary><strong>R866 — Distinct subdomain DNS A replies share one public address</strong> · Medium</summary>

- **Description:** Three distinct internal-client DNS A response names under one base domain resolve to the same public IPv4 within 60s; zone updates and wildcard configuration are not observable.
- **Category:** DnsThreat
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R866_MultiSubdomainSamePublicAnswerRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R867 — DNS SRV answer followed by matching public TLS SNI</strong> · Medium</summary>

- **Description:** A private DNS SRV reply advertises a hostname, followed by the recipient&#x27;s TLS connection bearing that SNI within 90s; DNS dynamic update or authentication is not observable.
- **Category:** DnsThreat
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R867_SrvReplyThenMatchingTlsSniRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R868 — Same DNS name receives private then public A answer across clients</strong> · Medium</summary>

- **Description:** Same private resolver answers one internal name with a private IPv4 and then a public IPv4 to a different client within 90s; split-horizon policy or unauthorized edits remain unknown.
- **Category:** DnsThreat
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R868_SplitScopeSameNameAReplyRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R876 — Three low-TTL DNS answers then SYN to latest public answer</strong> · Medium</summary>

- **Description:** Same private resolver gives three distinct low-TTL public A answers for one name to one private client, then the client SYNs to the last address; neither malicious fast-flux control nor process lineage is established.
- **Category:** DnsThreat
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R876_FastFluxDnsReplyThenAnswerSynRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R962 — CLI DNS A query then three distinct low-TTL public answers</strong> · Medium</summary>

- **Description:** Local curl/python-attributed complete UDP IN/A queries, each matched to a direct single-A low-TTL reply by wire transaction ID and reverse tuple, then three distinct public answers for the same querying PID, resolver and name within 45s. Legitimate CDN behavior and malicious fast flux are not distinguished.
- **Category:** DnsThreat
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R962_CliDnsQueryLowTtlReplyChurnRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Egress: 6 rules

<details>
<summary>Choose a rule from 6 Egress entries</summary>

<details>
<summary><strong>R009 — VPN / Proxy</strong> · Medium</summary>

- **Description:** VPN or proxy usage detected
- **Category:** Egress
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R009_VpnProxyRule.cs)
- **Detailed evidence and test scenarios:** [006-010](batches/RULE_BATCH_006-010.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R020 — Outbound SMTP Direct to Internet</strong> · Medium</summary>

- **Description:** Direct outbound SMTP to internet
- **Category:** Egress
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R020_OutboundSmtpDirectToInternetRule.cs)
- **Detailed evidence and test scenarios:** [016-020](batches/RULE_BATCH_016-020.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R026 — SMB / RPC to Internet</strong> · Medium</summary>

- **Description:** SMB or RPC to internet
- **Category:** Egress
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R026_SmbRpcToInternetRule.cs)
- **Detailed evidence and test scenarios:** [026-030](batches/RULE_BATCH_026-030.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R027 — Admin Service Egress</strong> · Medium</summary>

- **Description:** Administrative service exposed outbound
- **Category:** Egress
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R027_AdminServiceEgressRule.cs)
- **Detailed evidence and test scenarios:** [026-030](batches/RULE_BATCH_026-030.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R039 — ASN Novelty on Sensitive VLANs</strong> · Medium</summary>

- **Description:** New ASN from sensitive VLAN
- **Category:** Egress
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R039_AsnNoveltyOnSensitiveVlansRule.cs)
- **Detailed evidence and test scenarios:** [036-040](batches/RULE_BATCH_036-040.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R046 — Unauthorized VPN Protocol Egress</strong> · Medium</summary>

- **Description:** Unauthorized VPN protocol egress
- **Category:** Egress
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R046_UnauthorizedVpnProtocolEgressRule.cs)
- **Detailed evidence and test scenarios:** [046-050](batches/RULE_BATCH_046-050.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### EmailCollaboration: 20 rules

<details>
<summary>Choose a rule from 20 EmailCollaboration entries</summary>

<details>
<summary><strong>R313 — Direct SMTP To MX From Workstation</strong> · High</summary>

- **Description:** Detects Direct SMTP To MX From Workstation only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R313_DirectSMTPToMXFromWorkstationRule.cs)
- **Detailed evidence and test scenarios:** [311-315](batches/RULE_BATCH_311-315.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R314 — SMTP Authentication Failure Burst</strong> · Medium</summary>

- **Description:** Detects SMTP Authentication Failure Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R314_SMTPAuthenticationFailureBurstRule.cs)
- **Detailed evidence and test scenarios:** [311-315](batches/RULE_BATCH_311-315.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R315 — IMAP Login Failure Spray</strong> · Medium</summary>

- **Description:** Detects IMAP Login Failure Spray only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R315_IMAPLoginFailureSprayRule.cs)
- **Detailed evidence and test scenarios:** [311-315](batches/RULE_BATCH_311-315.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R316 — POP3 Cleartext Credential Exposure</strong> · High</summary>

- **Description:** Detects POP3 Cleartext Credential Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R316_POP3CleartextCredentialExposureRule.cs)
- **Detailed evidence and test scenarios:** [316-320](batches/RULE_BATCH_316-320.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R317 — Exchange Autodiscover External Spray</strong> · Medium</summary>

- **Description:** Detects Exchange Autodiscover External Spray only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R317_ExchangeAutodiscoverExternalSprayRule.cs)
- **Detailed evidence and test scenarios:** [316-320](batches/RULE_BATCH_316-320.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R318 — EWS Enumeration Burst</strong> · Medium</summary>

- **Description:** Detects EWS Enumeration Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R318_EWSEnumerationBurstRule.cs)
- **Detailed evidence and test scenarios:** [316-320](batches/RULE_BATCH_316-320.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R319 — OWA Admin Or ECP Probe</strong> · High</summary>

- **Description:** Detects OWA Admin Or ECP Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R319_OWAAdminOrECPProbeRule.cs)
- **Detailed evidence and test scenarios:** [316-320](batches/RULE_BATCH_316-320.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R320 — M365 Graph Mail Export Pattern</strong> · High</summary>

- **Description:** Detects M365 Graph Mail Export Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R320_M365GraphMailExportPatternRule.cs)
- **Detailed evidence and test scenarios:** [316-320](batches/RULE_BATCH_316-320.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R321 — Gmail API Bulk Message Read</strong> · High</summary>

- **Description:** Detects Gmail API Bulk Message Read only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R321_GmailAPIBulkMessageReadRule.cs)
- **Detailed evidence and test scenarios:** [321-325](batches/RULE_BATCH_321-325.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R322 — Mail Forwarding Rule Creation Indicator</strong> · High</summary>

- **Description:** Detects Mail Forwarding Rule Creation Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R322_MailForwardingRuleCreationIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [321-325](batches/RULE_BATCH_321-325.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R323 — Suspicious Attachment Download Burst</strong> · Medium</summary>

- **Description:** Detects Suspicious Attachment Download Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R323_SuspiciousAttachmentDownloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [321-325](batches/RULE_BATCH_321-325.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R324 — Phishing Kit URI Pattern</strong> · High</summary>

- **Description:** Detects Phishing Kit URI Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R324_PhishingKitURIPatternRule.cs)
- **Detailed evidence and test scenarios:** [321-325](batches/RULE_BATCH_321-325.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R325 — Lookalike Sender Domain Contact</strong> · Medium</summary>

- **Description:** Detects Lookalike Sender Domain Contact only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R325_LookalikeSenderDomainContactRule.cs)
- **Detailed evidence and test scenarios:** [321-325](batches/RULE_BATCH_321-325.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R326 — DMARC SPF DKIM Recon Query Burst</strong> · Low</summary>

- **Description:** Detects DMARC SPF DKIM Recon Query Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R326_DMARCSPFDKIMReconQueryBurstRule.cs)
- **Detailed evidence and test scenarios:** [326-330](batches/RULE_BATCH_326-330.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R327 — Slack OAuth App Install Callback</strong> · Medium</summary>

- **Description:** Detects Slack OAuth App Install Callback only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R327_SlackOAuthAppInstallCallbackRule.cs)
- **Detailed evidence and test scenarios:** [326-330](batches/RULE_BATCH_326-330.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R328 — Teams Webhook Abuse Indicator</strong> · High</summary>

- **Description:** Detects Teams Webhook Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R328_TeamsWebhookAbuseIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [326-330](batches/RULE_BATCH_326-330.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R329 — SharePoint Bulk Download Pattern</strong> · High</summary>

- **Description:** Detects SharePoint Bulk Download Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R329_SharePointBulkDownloadPatternRule.cs)
- **Detailed evidence and test scenarios:** [326-330](batches/RULE_BATCH_326-330.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R330 — OneDrive Anonymous Share Link Mass Access</strong> · Medium</summary>

- **Description:** Detects OneDrive Anonymous Share Link Mass Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R330_OneDriveAnonymousShareLinkMassAccessRule.cs)
- **Detailed evidence and test scenarios:** [326-330](batches/RULE_BATCH_326-330.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R331 — Calendar Invite Phishing Link Pattern</strong> · Medium</summary>

- **Description:** Candidate R331 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** EmailCollaboration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R331_CalendarInvitePhishingLinkPatternRule.cs)
- **Detailed evidence and test scenarios:** [331-335](batches/RULE_BATCH_331-335.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R332 — Email Archive Export Download</strong> · High</summary>

- **Description:** Candidate R332 requires authenticated operation and outcome provenance; packet-only indicators cannot establish the named behavior.
- **Category:** EmailCollaboration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R332_EmailArchiveExportDownloadRule.cs)
- **Detailed evidence and test scenarios:** [331-335](batches/RULE_BATCH_331-335.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### EvasionInfra: 56 rules

<details>
<summary>Choose a rule from 56 EvasionInfra entries</summary>

<details>
<summary><strong>R258 — ICMP Destination Unreachable Spike</strong> · Medium</summary>

- **Description:** Detects icmp destination unreachable spike only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R258_IcmpDestinationUnreachableSpikeRule.cs)
- **Detailed evidence and test scenarios:** [256-260](batches/RULE_BATCH_256-260.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R259 — TCP Reset Storm</strong> · Medium</summary>

- **Description:** Detects tcp reset storm only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R259_TcpResetStormRule.cs)
- **Detailed evidence and test scenarios:** [256-260](batches/RULE_BATCH_256-260.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R260 — Rare TCP Option Fingerprint</strong> · Medium</summary>

- **Description:** Detects rare tcp option fingerprint only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R260_RareTcpOptionFingerprintRule.cs)
- **Detailed evidence and test scenarios:** [256-260](batches/RULE_BATCH_256-260.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R261 — TTL Anomaly To Same Service</strong> · Low</summary>

- **Description:** Detects ttl anomaly to same service only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R261_TtlAnomalyToSameServiceRule.cs)
- **Detailed evidence and test scenarios:** [261-265](batches/RULE_BATCH_261-265.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R262 — Suspicious Packet Fragmentation</strong> · High</summary>

- **Description:** Detects suspicious packet fragmentation only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R262_SuspiciousPacketFragmentationRule.cs)
- **Detailed evidence and test scenarios:** [261-265](batches/RULE_BATCH_261-265.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R263 — User-Space Proxy Process Egress</strong> · Medium</summary>

- **Description:** Detects user-space proxy process egress only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R263_UserSpaceProxyProcessEgressRule.cs)
- **Detailed evidence and test scenarios:** [261-265](batches/RULE_BATCH_261-265.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R264 — Tor Directory Or Guard Connection</strong> · High</summary>

- **Description:** Detects tor directory or guard connection only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R264_TorDirectoryOrGuardConnectionRule.cs)
- **Detailed evidence and test scenarios:** [261-265](batches/RULE_BATCH_261-265.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R265 — Public VPN Proxy Domain Contact</strong> · Medium</summary>

- **Description:** Detects public vpn proxy domain contact only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R265_PublicVpnProxyDomainContactRule.cs)
- **Detailed evidence and test scenarios:** [261-265](batches/RULE_BATCH_261-265.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R266 — New Process Initiating Network Egress</strong> · Low</summary>

- **Description:** Detects new process initiating network egress only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R266_NewProcessInitiatingNetworkEgressRule.cs)
- **Detailed evidence and test scenarios:** [266-270](batches/RULE_BATCH_266-270.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R267 — Suspicious Process Name Network Egress</strong> · High</summary>

- **Description:** Detects suspicious process name network egress only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R267_SuspiciousProcessNameNetworkEgressRule.cs)
- **Detailed evidence and test scenarios:** [266-270](batches/RULE_BATCH_266-270.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R268 — DNS Or HTTP From Script Interpreter</strong> · High</summary>

- **Description:** Detects dns or http from script interpreter only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R268_DnsOrHttpFromScriptInterpreterRule.cs)
- **Detailed evidence and test scenarios:** [266-270](batches/RULE_BATCH_266-270.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R269 — Security Tool Update Block Indicator</strong> · Medium</summary>

- **Description:** Detects security tool update block indicator only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R269_SecurityToolUpdateBlockIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [266-270](batches/RULE_BATCH_266-270.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R270 — Detection Pipeline Tampering Indicator</strong> · Critical</summary>

- **Description:** Detects detection pipeline tampering indicator only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R270_DetectionPipelineTamperingIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [266-270](batches/RULE_BATCH_266-270.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R271 — Threat Feed IOC With Low Reputation Overlap</strong> · Critical</summary>

- **Description:** Detects threat feed ioc with low reputation overlap only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R271_ThreatFeedIocWithLowReputationOverlapRule.cs)
- **Detailed evidence and test scenarios:** [271-275](batches/RULE_BATCH_271-275.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R272 — Multi-Signal Rule Stack Surge From Host</strong> · High</summary>

- **Description:** Detects multi-signal rule stack surge from host only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.
- **Category:** EvasionInfra
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R272_MultiSignalRuleStackSurgeFromHostRule.cs)
- **Detailed evidence and test scenarios:** [271-275](batches/RULE_BATCH_271-275.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R622 — Notepad Process External TCP Egress</strong> · Medium</summary>

- **Description:** locally resolved process and external TCP flow: specific workbook candidate, detection only; Best-effort Windows process-to-flow mapping lacks authenticated execution or path identity. This is conditional evidence only.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R622_NotepadExternalTcpEgressRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R623 — Dialer Process External TCP Egress</strong> · Medium</summary>

- **Description:** locally resolved process and external TCP flow: specific workbook candidate, detection only; Sigma requires System32 path, which is not reliably present in ProcessName. Basename cannot establish signature or path.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R623_DialerExternalTcpEgressRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R624 — AddInUtil Process External TCP Egress</strong> · High</summary>

- **Description:** locally resolved process and external TCP flow: specific workbook candidate, detection only; PID/name can be resolved only on visible local sockets and may be missing or stale. No causal execution claim.
- **Category:** EvasionInfra
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R624_AddInUtilExternalTcpEgressRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R625 — Equation Editor Process External TCP Egress</strong> · High</summary>

- **Description:** locally resolved process and external TCP flow: specific workbook candidate, detection only; Process identity is best-effort and no signed executable path or malicious payload is established.
- **Category:** EvasionInfra
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R625_EquationEditorExternalTcpEgressRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R630 — PowerShell client outbound WinRM to public IP</strong> · Medium</summary>

- **Description:** Original R2215; R074 WinRM sweep and R027 generic admin egress; here attributed PowerShell client on WinRM port to public IP. Only observable packet fields, no asserted outcome.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R630_PowerShellOutboundPublicWinRmRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R631 — Unusual command interpreter outbound RDP</strong> · Medium</summary>

- **Description:** Original R2221; R073 RDP lateral burst and R124 ingress exposure; this is specific unusual local process to a public RDP endpoint. Only observable packet fields, no asserted outcome.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R631_CommandInterpreterOutboundRdpRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R632 — Svchost RDP loopback flow candidate</strong> · Low</summary>

- **Description:** Original R2238; R518 generic reverse SSH tunnel; this only observes the characteristic local loopback 3389 source-flow shape. Only observable packet fields, no asserted outcome.
- **Category:** EvasionInfra
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R632_SvchostRdpLoopbackFlowRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R633 — Certutil external TCP request to unusual service</strong> · Medium</summary>

- **Description:** Original R2958; R266 first-seen process egress; this matches exact certutil basename and specific four ports regardless of first seen. Only observable packet fields, no asserted outcome.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R633_CertutilExternalServiceTcpRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R634 — Windows script host external TCP other than HTTP/DNS</strong> · Medium</summary>

- **Description:** Original R2963; R268 already matches script interpreter HTTP/DNS; this only matches non-HTTP/non-DNS external TCP. Only observable packet fields, no asserted outcome.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R634_WindowsScriptHostNonHttpOutboundTcpRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R635 — Nonbrowser Windows system host to public dead-drop service</strong> · Low</summary>

- **Description:** Original R2350; R104 first-time cloud uploads, R110 service API egress; this requires a local nonbrowser process plus TLS SNI to a particular public service, no dead-drop attribution. Only observable packet fields, no asserted outcome.
- **Category:** EvasionInfra
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R635_NonBrowserProcessDeadDropHostRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R638 — Process outbound TCP contact across multiple callback-associated ports</strong> · Medium</summary>

- **Description:** Process outbound TCP contact across multiple callback-associated ports. Observed evidence only; The workbook&#x27;s Linux log producer is absent; only a best-effort locally attributed Windows TCP-flow analogue is implemented. Distinct port contact is not confirmed malware.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R638_MultiPortSuspiciousCallbackProcessEgressRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R639 — Local process TLS SNI contact to ngrok developer-domain variants</strong> · Low</summary>

- **Description:** Local process TLS SNI contact to ngrok developer-domain variants. Observed evidence only; TLS SNI alone does not establish an initiated connection, use of a tunnel or payload transfer; approved ngrok deployments are common.
- **Category:** EvasionInfra
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R639_NgrokDevProcessTlsSniEgressRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R640 — Local process TLS SNI contact to regional ngrok tunnel endpoints</strong> · Low</summary>

- **Description:** Local process TLS SNI contact to regional ngrok tunnel endpoints. Observed evidence only; No established tunnel, authentication, ownership or file transfer can be inferred from SNI and best-effort PID attribution.
- **Category:** EvasionInfra
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R640_NgrokRegionalTunnelProcessTlsSniRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R647 — Known miner process contacting external pool-associated TCP port</strong> · Medium</summary>

- **Description:** Known miner process contacting external pool-associated TCP port. R178 detects miner pool DNS, R266 first-seen process; this requires exact miner basename and port to public IP.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R647_MinerProcessPublicPoolPortEgressRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R650 — Curl/Wget attributed process outbound public subnet fanout</strong> · Medium</summary>

- **Description:** Curl/Wget attributed process outbound public subnet fanout. R017 sweeps internal targets; R036 heavy upload to one target. This requires one process+PID, three public /24s.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R650_CurlWgetProcessPublicSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R661 — PowerShell or script-host process to external mail-service port</strong> · Medium</summary>

- **Description:** PowerShell or script-host process to external mail-service port. R020 and R313 detect generic outbound SMTP; this specifically requires a scripting process with PID and also includes IMAP/POP3 port families.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R661_ScriptHostExternalMailServiceTcpEgressRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R680 — Unusual local process SYN fanout to three internal hosts</strong> · Medium</summary>

- **Description:** Unusual local process SYN fanout to three internal hosts; PID enrichment is best-effort, and an internal SYN fanout is not proof of proxying or lateral command execution.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R680_UnusualProcessInternalPrivateHostFanoutRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R700 — Rundll32-associated external WebDAV request</strong> · Medium</summary>

- **Description:** Rundll32-associated external WebDAV request. DavSetCookie command line, parent process, code launch and CVE exploitation are not observed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R700_Rundll32ExternalWebDavRequestRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R701 — Net.exe-associated external WebDAV request</strong> · Medium</summary>

- **Description:** Net.exe-associated external WebDAV request. The `net use` command line and successful mount result are not observable from the packet record.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R701_NetExeExternalWebDavRequestRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R720 — WMIC process cleartext external XSL fetch</strong> · Medium</summary>

- **Description:** A locally attributed wmic.exe process issues a cleartext outbound HTTP GET for an .xsl or .xslt resource. The /format command-line switch, XSL script contents, in-memory execution, application-control bypass, and code execution are not observed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R720_WmicExternalXslHttpFetchRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R735 — ESXi process HTTP/TLS service-port mismatch</strong> · Low</summary>

- **Description:** hostd, vpxa, or vmx is associated with parsed HTTP on VMware service ports 902/903 or TLS on cleartext web ports 80/8000/8080. Certificate validity, payload impersonation, malicious tunneling and compromise are not observed.
- **Category:** EvasionInfra
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R735_EsxiProcessWebProtocolPortMismatchRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R743 — ESXi management-process fixed-size uncommon-port egress cadence</strong> · Low</summary>

- **Description:** hostd, vpxa, or vmx is associated with three similarly sized raw TCP payload observations to one public uncommon port at regular 9–31 second intervals. Encoded data, lookup tables, file contents, tunnel establishment and command-and-control are not observed.
- **Category:** EvasionInfra
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R743_EsxiManagementProcessFixedSizeEgressCadenceRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R826 — Notepad-attributed SYNs to two distinct public peers</strong> · Medium</summary>

- **Description:** The local Notepad process has two separate outbound TCP SYN attempts; code injection, execution and connection success are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R826_NotepadDistinctExternalSynRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R846 — Microsoft Dialer-attributed public TCP/443 SYN</strong> · Medium</summary>

- **Description:** A locally attributed dialer.exe initiates a typed public TCP/443 SYN; neither injection, C2, connection completion nor actor intent is proven.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R846_DialerExternalSynRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R847 — AddInUtil-attributed public TCP/8443 SYN</strong> · Medium</summary>

- **Description:** Addinutil.exe local process attribution to a public TCP/8443 SYN; no remote payload, C2 or successful connection inferred.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R847_AddinUtilExternalSynRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R848 — Equation Editor-attributed public HTTP-port SYN</strong> · Medium</summary>

- **Description:** Legacy Eqnedt32.exe process attributed to a public TCP/80 SYN; no document exploit, code injection or successful connection asserted.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R848_Eqnedt32ExternalSynRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R857 — Awk-attributed public TLS/8443 medium payload</strong> · Medium</summary>

- **Description:** An awk-attributed public TLS/8443 TCP payload has 720–820 bytes; process command line, decoded scripts and asset role are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R857_AwkUnusualPublicTlsPayloadRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R860 — Regsvr32-attributed UDP/1194 payload fanout</strong> · Medium</summary>

- **Description:** Regsvr32-attributed UDP/1194 payload packets reach three distinct public peers in 60s; DLL invocation, endpoint lineage and exfiltration are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R860_Regsvr32PublicUdp1194FanoutRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R900 — Regasm or Regsvcs-attributed public SYN then TLS data</strong> · Medium</summary>

- **Description:** Same private source, public peer, local regasm/regsvcs PID and source port SYN to TCP/443 followed by TLS-marked TCP data in 45 seconds; COM registration, assembly load, execution and C2 are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R900_RegasmPublicSynThenTlsRule.cs)
- **Detailed evidence and test scenarios:** [896-900](batches/RULE_BATCH_896-900.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R905 — MMC private SMB SYN then public TLS data</strong> · Medium</summary>

- **Description:** Same private source and mmc PID initiate TCP/445 to a private peer then TLS-marked TCP/443 data to a public peer within 45s; MMC document loading, COM activation, DLL loading and causality are not observed.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R905_MmcPrivateSmbThenPublicTlsRule.cs)
- **Detailed evidence and test scenarios:** [901-905](batches/RULE_BATCH_901-905.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R914 — Rundll32 public SYN then future-dated peer certificate</strong> · Medium</summary>

- **Description:** Rundll32 TCP/443 SYN followed by reverse-tuple certificate metadata with validity start more than 24 hours in the future. Certificate acceptance, library load and C2 are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R914_Rundll32SynThenFutureCertificateRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R929 — ClickOnce dfsvc manifest GET then public TLS</strong> · Medium</summary>

- **Description:** Same private source and dfsvc PID GETs a public .application path then sends public TLS/443 data within 45s. ClickOnce install, manifest validation, child process and execution are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R929_DfsvcManifestThenPublicTlsRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R930 — MSBuild public targets GET then public SMB SYN</strong> · Medium</summary>

- **Description:** Same local MSBuild PID retrieves a .targets path over cleartext public HTTP then initiates TCP/445 to a public peer. Build execution, downloaded contents and SMB authentication are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R930_MsbuildTargetsGetThenPublicSmbRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R935 — Hostd public SYN then equal issuer/subject certificate</strong> · Medium</summary>

- **Description:** Hostd/vpxa TCP/443 SYN followed by reverse-flow visible TLS certificate whose issuer and subject strings are equal. Self-signature validity, vendor trust and C2 are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R935_HostdSynThenEqualIssuerSubjectCertRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R936 — Python public TLS SYN then inverted certificate validity</strong> · Medium</summary>

- **Description:** Python-attributed public TCP/443 SYN followed by reverse-flow certificate metadata with NotAfter earlier than NotBefore. Parser observation only; certificate verification, acceptance, crypto library and compromise are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R936_PythonPublicTlsCertificateValidityInversionRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R943 — InstallUtil public MSI GET then same-PID TLS</strong> · Medium</summary>

- **Description:** InstallUtil PID sends public HTTP GET for an MSI path then public TLS/443 data. Signed binary status, installer contents, registration and execution are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R943_InstallutilPublicMsiGetThenTlsRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R944 — MSHTA public HTA GET then private WinRM SYN</strong> · Medium</summary>

- **Description:** Same private source and MSHTA PID sends public HTTP GET for .hta then private TCP/5985 SYN. HTA execution, child process, authentication and remote command are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R944_MshtaHtaGetThenPrivateWinRmSynRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R951 — Teams public TLS then same-PID public SMB SYN</strong> · Medium</summary>

- **Description:** Same local Teams PID sends public TLS/443 with visible SNI then public TCP/445 SYN to a different or same peer. Electron argument abuse, child process, app-resource change and execution are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R951_TeamsPublicTlsThenPublicSmbRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R952 — Wscript public VBS GET then same-PID public TLS</strong> · Medium</summary>

- **Description:** Wscript PID retrieves a public .vbs path then sends public TLS/443 data. SyncAppvPublishingServer invocation, embedded PowerShell, script content and execution are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R952_WscriptPublicVbsGetThenTlsRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R953 — Cscript private JS GET then same-peer RPC SYN</strong> · Medium</summary>

- **Description:** Same private cscript PID retrieves a .js path from a private peer then TCP/135 SYN to that peer. Signature status, script arguments, child process, RPC execution and authorization are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R953_CscriptPrivateJsGetThenRpcSynRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R965 — Spoolsv public DLL GET then same-peer SMB SYN</strong> · Medium</summary>

- **Description:** Same spoolsv PID retrieves public DLL-suffix HTTP path then TCP/445 SYN to same public peer. Print-monitor registry write, DLL load, AddMonitor call and persistence are unknown.
- **Category:** EvasionInfra
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R965_SpoolsvPublicDllGetThenSmbSynRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### EvasionTunnel: 61 rules

<details>
<summary>Choose a rule from 61 EvasionTunnel entries</summary>

<details>
<summary><strong>R513 — SSH Dynamic SOCKS Proxy Use</strong> · High</summary>

- **Description:** Detects SSH Dynamic SOCKS Proxy Use only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R513_SSHDynamicSOCKSProxyUseRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R514 — Chisel Tunnel Handshake</strong> · High</summary>

- **Description:** Detects Chisel Tunnel Handshake only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R514_ChiselTunnelHandshakeRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R515 — FRP Tunnel Handshake</strong> · High</summary>

- **Description:** Detects FRP Tunnel Handshake only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R515_FRPTunnelHandshakeRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R516 — Cloudflared Tunnel Handshake</strong> · High</summary>

- **Description:** Detects Cloudflared Tunnel Handshake only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R516_CloudflaredTunnelHandshakeRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R517 — Ngrok Tunnel Handshake V2</strong> · High</summary>

- **Description:** Detects Ngrok Tunnel Handshake V2 only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R517_NgrokTunnelHandshakeV2Rule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R518 — Reverse SSH Tunnel Pattern</strong> · High</summary>

- **Description:** Detects Reverse SSH Tunnel Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R518_ReverseSSHTunnelPatternRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R519 — DNS Over QUIC Unapproved Resolver</strong> · High</summary>

- **Description:** Detects DNS Over QUIC Unapproved Resolver only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R519_DNSOverQUICUnapprovedResolverRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R520 — MASQUE CONNECT UDP Proxy Use</strong> · Medium</summary>

- **Description:** Detects MASQUE CONNECT UDP Proxy Use only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R520_MASQUECONNECTUDPProxyUseRule.cs)
- **Detailed evidence and test scenarios:** [511-520](batches/RULE_BATCH_511-520.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R521 — HTTP CONNECT To Non Proxy Port</strong> · Medium</summary>

- **Description:** Detects HTTP CONNECT To Non Proxy Port only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R521_HTTPCONNECTToNonProxyPortRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R522 — WebSocket Tunnel To IP Literal</strong> · High</summary>

- **Description:** Detects WebSocket Tunnel To IP Literal only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R522_WebSocketTunnelToIPLiteralRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R523 — Domain Fronting Host SNI Mismatch</strong> · High</summary>

- **Description:** Detects Domain Fronting Host SNI Mismatch only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R523_DomainFrontingHostSNIMismatchRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R524 — ECH To Unapproved Provider</strong> · Medium</summary>

- **Description:** Detects ECH To Unapproved Provider only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R524_ECHToUnapprovedProviderRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R525 — QUIC Connection ID Rotation Burst</strong> · Medium</summary>

- **Description:** Detects QUIC Connection ID Rotation Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R525_QUICConnectionIDRotationBurstRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R526 — Packet Size Mimicry Beacon</strong> · Medium</summary>

- **Description:** Detects Packet Size Mimicry Beacon only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R526_PacketSizeMimicryBeaconRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R527 — Sleepy Beacon Long Gap Pattern</strong> · Medium</summary>

- **Description:** Detects Sleepy Beacon Long Gap Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R527_SleepyBeaconLongGapPatternRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R528 — User Agent Randomization Burst</strong> · Medium</summary>

- **Description:** Detects User Agent Randomization Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R528_UserAgentRandomizationBurstRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R662 — IDE process observed using Visual Studio developer-tunnel TLS SNI</strong> · Low</summary>

- **Description:** IDE process observed using Visual Studio developer-tunnel TLS SNI. R516/R517 handle other tunneling providers; this exact Visual Studio development-tunnel SNI and IDE process conjunction differs.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R662_IdeProcessVisualStudioDevTunnelTlsSniEgressRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R667 — Script process publishes MQTT control-topic request to external broker</strong> · Medium</summary>

- **Description:** Script process publishes MQTT control-topic request to external broker. MQTT parser labels a publish request; no client identity, broker acceptance, C2 or actuation outcome is established.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R667_ScriptProcessMqttControlTopicPublishRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R670 — Four regularly spaced fixed-size ICMP echo requests</strong> · Low</summary>

- **Description:** Four regularly spaced fixed-size ICMP echo requests. A regular ping sequence is often benign and does not prove C2 or tunneling.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R670_RegularFixedLengthIcmpEchoSequenceRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R674 — Same local PID receives public TCP SYN then initiates external high-port SYN</strong> · Medium</summary>

- **Description:** Same local PID receives public TCP SYN then initiates external high-port SYN. Two SYNs do not prove process spawning, packet forwarding, NAT, an established proxy or a C2 relay.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R674_SameProcessInboundToOutboundPublicTcpSynSequenceRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R675 — System utility TLS SNI contact to web collaboration endpoint</strong> · Low</summary>

- **Description:** System utility TLS SNI contact to web collaboration endpoint. No upload/download, persistent session, malicious C2 use, TLS content, or reliable process executable identity.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R675_UnusualSystemUtilityTlsSniToWebCollaborationHostRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R681 — Unusual local process contacts two public peers on proxy-associated TCP ports</strong> · Medium</summary>

- **Description:** Unusual local process contacts two public peers on proxy-associated TCP ports; No SOCKS handshake, established proxy, C2 relay or forwarded payload is observed.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R681_UnusualProcessDualPublicProxyPortSynRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R694 — NPS npc.exe process associated with external TCP egress</strong> · Medium</summary>

- **Description:** NPS npc.exe process associated with external TCP egress. No NPS command line, vkey/password, server mode, proxy handshake or actual traffic forwarding is observed.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R694_NpsNpcProcessExternalTcpEgressRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R695 — IOX iox.exe process associated with external TCP egress</strong> · Medium</summary>

- **Description:** IOX iox.exe process associated with external TCP egress. No fwd/proxy command-line mode, listener role, SOCKS semantics, tunnel establishment or forwarded bytes are observed.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R695_IoxProcessExternalTcpEgressRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R703 — Script-like process emits repeated raw UDP payloads to one public high-port peer</strong> · Low</summary>

- **Description:** Script-like process emits repeated raw UDP payloads to one public high-port peer. Five UDP datagrams do not prove non-application C2, exfiltration, payload semantics or server receipt.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R703_ScriptProcessRepeatedPublicUdpPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R704 — Unattributed private host receives internal high-port SYN then initiates admin-service SYN to another private host</strong> · Low</summary>

- **Description:** Unattributed private host receives internal high-port SYN then initiates admin-service SYN to another private host. Two SYN packets do not prove a proxy, C2 relay, ESXi shell tool, accepted connection or forwarded payload.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R704_UnattributedInternalRelaySynSequenceRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R705 — Unattributed private host receives public high-port SYN then initiates SYN to a different public peer</strong> · Low</summary>

- **Description:** Unattributed private host receives public high-port SYN then initiates SYN to a different public peer. Host-level SYN correlation does not establish netcat/socat, reverse tunnel, traffic bridging or successful connections.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R705_UnattributedPublicBridgeSynSequenceRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R706 — Public source three-port knock followed by private-host admin SYN</strong> · Medium</summary>

- **Description:** A public source sends SYNs to exactly three distinct high ports on one private host, then an admin-service SYN within 60 seconds. This does not prove closed-port responses, firewall changes, listener activation, magic-packet handling, or a successful session.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R706_DirectHostPortKnockThenAdminSynRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R711 — Plink or PuTTY process contacts public SSH then internal admin service</strong> · Medium</summary>

- **Description:** The same best-effort local Plink/PuTTY PID first sends an outbound SSH SYN to a public peer and then an outbound SYN to a different private admin-service peer within 30 seconds. This does not prove SSH port forwarding, encapsulated RDP/SMB, authentication, or an established tunnel.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R711_PlinkSshThenInternalAdminLegRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R712 — Socat process receives public SYN then contacts internal admin service</strong> · Medium</summary>

- **Description:** The same best-effort local Socat PID receives a public high-port SYN and then initiates a SYN from that local host to a different private admin-service peer within 30 seconds. Two SYNs do not prove port forwarding, encapsulation, payload relay, or a successful connection.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R712_SocatPublicIngressThenInternalAdminLegRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R713 — Netcat process external high-port SYN followed by raw TCP payload</strong> · Medium</summary>

- **Description:** The same best-effort Netcat/Ncat PID sends an outbound SYN to a public uncommon high port and then a raw TCP payload observation on the same tuple within 30 seconds. Command-line -e/-c flags, shell execution, server acceptance, and reverse-shell semantics are not observed.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R713_NetcatExternalHighPortConnectPayloadRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R721 — Hybrid Connection Manager TLS SNI to Azure Service Bus</strong> · Low</summary>

- **Description:** HybridConnectionManager.exe is associated with outbound TLS to a servicebus.windows.net SNI. Service state, Hybrid Connection configuration, authentication, successful relay establishment, and malicious intent are not observed.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R721_HybridConnectionManagerServiceBusTlsRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R741 — Hypervisor management process TLS contact to dead-drop service</strong> · Low</summary>

- **Description:** hostd, vpxa, or vmx is associated with outbound TLS/443 to a bounded paste/Gist text-storage service. Retrieved content, embedded secondary C2 indicators, response data and malicious intent are not observed.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R741_HypervisorProcessDeadDropTlsContactRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R742 — BusyBox/curl/wget external TLS heartbeat-shaped cadence</strong> · Low</summary>

- **Description:** busybox, curl, or wget is associated with three similarly sized TLS/443 payload observations to one public peer at regular 9–31 second intervals. Common dead-drop, cloud-storage, code-repository and public-IP discovery hosts are excluded. Shell origin, HTTP content, command-and-control and server responses are not observed.
- **Category:** EvasionTunnel
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R742_BusyBoxCliWebHeartbeatCadenceRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R744 — ESXi management-process public proxy-port fanout</strong> · Medium</summary>

- **Description:** hostd, vpxa, or vmx initiates TCP SYNs to three distinct public peers on proxy/tunnel-associated ports within one minute. Traffic forwarding, relay chaining, authenticated proxy use, multi-hop routing and malicious intent are not observed.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R744_EsxiManagementProcessProxyPortFanoutRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R758 — Public uncommon-port trigger followed by reverse SYN to origin</strong> · Medium</summary>

- **Description:** A low-volume public-to-private TCP SYN to an uncommon high port is followed within 90 seconds by a TCP SYN from that private host back to the same public source. Packet-filter installation, raw-socket activity, accepted sessions, reverse-shell semantics and compromise are not observed.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R758_PublicUncommonTriggerThenReverseSynRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R769 — Perl/Ruby high-rate cleartext HTTP request burst</strong> · Medium</summary>

- **Description:** perl or ruby is associated with twelve parser-backed cleartext HTTP GET/POST requests to one public peer within ten seconds. Process novelty, response volume, request semantics and command-and-control are not observed.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R769_LinuxPerlRubyHttpRequestBurstRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R770 — Windows LOLBIN outbound web-traffic burst</strong> · Medium</summary>

- **Description:** regsvr32, mshta, wscript, or cscript is associated with eight HTTP request or TLS/443 payload observations to one public peer within twenty seconds. Process novelty, response volume, script content and command-and-control are not observed.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R770_WindowsLolbinWebTrafficBurstRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R776 — Windows PowerShell HTTP POST burst to text-storage host</strong> · Medium</summary>

- **Description:** Windows PowerShell HTTP POST burst to text-storage host. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R776_WindowsPowerShellPasteHttpPostBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R777 — Windows git HTTP POST burst to code-repository host</strong> · Medium</summary>

- **Description:** Windows git HTTP POST burst to code-repository host. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R777_WindowsGitRepositoryHttpPostBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R778 — Windows Excel TLS/443 burst to cloud-storage host</strong> · Medium</summary>

- **Description:** Windows Excel TLS/443 burst to cloud-storage host. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R778_WindowsExcelCloudStorageTlsBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R779 — Windows 7-Zip uncommon-port TLS payload burst</strong> · Medium</summary>

- **Description:** Windows 7-Zip uncommon-port TLS payload burst. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R779_Windows7ZipUncommonPortTlsBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R780 — Windows PowerShell TCP/21 payload burst</strong> · Medium</summary>

- **Description:** Windows PowerShell TCP/21 payload burst. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R780_WindowsPowerShellFtpPortPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R781 — ESXi hostd TLS/443 burst to text-storage host</strong> · Medium</summary>

- **Description:** ESXi hostd TLS/443 burst to text-storage host. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R781_EsxiHostdTextStorageTlsBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R782 — Linux tar TLS/443 burst to cloud-storage host</strong> · Medium</summary>

- **Description:** Linux tar TLS/443 burst to cloud-storage host. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R782_LinuxTarCloudStorageTlsBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R783 — Linux rsync TCP/21 payload burst</strong> · Medium</summary>

- **Description:** Linux rsync TCP/21 payload burst. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R783_LinuxRsyncFtpPortPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R784 — macOS osascript HTTP POST burst to text-storage host</strong> · Medium</summary>

- **Description:** macOS osascript HTTP POST burst to text-storage host. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R784_MacOsascriptTextStorageHttpPostBurstRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R785 — macOS launchd fixed-size TLS/443 egress cadence</strong> · Medium</summary>

- **Description:** macOS launchd fixed-size TLS/443 egress cadence. This is a narrow packet/process association, not proof of file access, transfer completion, command execution, exfiltration, or compromise.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R785_MacLaunchdFixedSizeTlsCadenceRule.cs)
- **Detailed evidence and test scenarios:** [776-785](batches/RULE_BATCH_776-785.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R786 — Large DNS-over-TCP TXT query burst toward public resolver</strong> · Medium</summary>

- **Description:** Large DNS-over-TCP TXT query burst toward public resolver. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R786_TcpDnsTxtLargeQueryBurstRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R787 — DNS A query followed by process-attributed unusual public SYN</strong> · Medium</summary>

- **Description:** DNS A query followed by process-attributed unusual public SYN. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R787_DnsThenUnusualPublicConnectRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R790 — Public server certificate issuer changes across captured handshakes</strong> · Medium</summary>

- **Description:** Public server certificate issuer changes across captured handshakes. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R790_RemoteTlsIssuerShiftRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R792 — hostd-attributed FTP STOR request then parsed TFTP WRQ egress</strong> · Medium</summary>

- **Description:** hostd-attributed FTP STOR request then parsed TFTP WRQ egress. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R792_EsxiFtpThenTftpEgressRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R793 — Public proxy-port SYN followed by nginx-attributed external SYN</strong> · Medium</summary>

- **Description:** Public proxy-port SYN followed by nginx-attributed external SYN. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R793_PublicProxyIngressThenNginxEgressRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R796 — frpc-attributed internal proxy-leg then public TLS-port SYN</strong> · Medium</summary>

- **Description:** frpc-attributed internal proxy-leg then public TLS-port SYN. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R796_FrpcInternalThenExternalSynRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R798 — DNS A query followed by same-process repeating TLS/SNI cadence</strong> · Medium</summary>

- **Description:** DNS A query followed by same-process repeating TLS/SNI cadence. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R798_DnsThenRecurringTlsSniRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R799 — process-linked DNS TXT query then cleartext HTTP POST to same host</strong> · Medium</summary>

- **Description:** process-linked DNS TXT query then cleartext HTTP POST to same host. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R799_DnsTxtThenSameHostHttpPostRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R805 — five distinct long base32-shaped TXT subdomain questions</strong> · Medium</summary>

- **Description:** five distinct long base32-shaped TXT subdomain questions. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R805_EncodedDnsTxtDistinctQueryBurstRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R810 — frpc-attributed versioned QUIC fanout to three public peers</strong> · Medium</summary>

- **Description:** frpc-attributed versioned QUIC fanout to three public peers. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R810_FrpcQuicPublicPeerFanoutRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R812 — openssl-attributed recurrent UDP/4444 public payload traffic</strong> · Medium</summary>

- **Description:** openssl-attributed recurrent UDP/4444 public payload traffic. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R812_OpensslPublicUdpPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R815 — osascript attributed alternating short and long external TLS packets</strong> · Medium</summary>

- **Description:** osascript attributed alternating short and long external TLS packets. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R815_OsascriptAlternatingTlsPayloadSizesRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R818 — IDE marketplace TLS contact then different-peer TCP/8443 SYN</strong> · Medium</summary>

- **Description:** IDE marketplace TLS contact then different-peer TCP/8443 SYN. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** EvasionTunnel
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R818_IdeMarketplaceThenUnusualTlsPortRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Execution: 11 rules

<details>
<summary>Choose a rule from 11 Execution entries</summary>

<details>
<summary><strong>R752 — msiexec cleartext HTTP retrieval of remote installer package</strong> · Medium</summary>

- **Description:** msiexec is associated with an outbound cleartext HTTP GET whose path ends in .msi, .msp, or .mst. Command-line arguments, package signature, download completion, installation, DLL execution and compromise are not observed.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R752_MsiexecRemoteMsiHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R762 — MSBuild external TLS payload burst</strong> · Medium</summary>

- **Description:** msbuild.exe is associated with four substantial TLS/443 payload observations to one public peer within two minutes. Project path, command line, child process, module load, file write, injection behavior and malicious proxy execution are not observed.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R762_MsbuildExternalTlsPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R806 — Docker registry manifest GET then xmrig pool-service payload</strong> · Medium</summary>

- **Description:** Docker manifest HTTP GET followed by same-host xmrig public TCP/3333 payload. No container creation, launch or compromise inferred.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R806_DockerManifestThenMinerPoolPayloadRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R817 — curl script URL GET then shell-attributed different-peer TLS payload</strong> · Medium</summary>

- **Description:** curl script URL GET then shell-attributed different-peer TLS payload. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R817_ScriptHttpGetThenShellPublicEgressRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R820 — Safari JavaScript GET then osascript different-peer TLS/8443</strong> · Medium</summary>

- **Description:** Safari JavaScript GET then osascript different-peer TLS/8443. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R820_SafariJavascriptThenOsascriptTlsRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R831 — MpCmdRun-attributed archive GET from public direct-IP host</strong> · Medium</summary>

- **Description:** MpCmdRun process-attributed HTTP archive URL is observable; command-line DownloadFile mode, disk path and successful download are unavailable.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R831_MpCmdRunDirectIpArchiveGetRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R833 — Word remote template GET followed by PowerShell other-peer TLS</strong> · Medium</summary>

- **Description:** Same local IP Word template HTTP request and later PowerShell public TLS egress; no parent process lineage or malicious document is observed.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R833_WordRemoteTemplateThenPowerShellTlsRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R841 — Browser JavaScript GET then Python different-peer TLS</strong> · Medium</summary>

- **Description:** Local Firefox/Chromium GET of a .js path followed by python/python3 TLS/8443 to a different public peer; no drive-by code execution or parentage inferred.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R841_BrowserScriptGetThenPythonTlsRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R861 — Thunderbird ZIP GET followed by bash TLS to another peer</strong> · Medium</summary>

- **Description:** A thunderbird-attributed cleartext .zip GET precedes bash-attributed public TLS/8443 to a different peer inside 60s; attachment opening and process lineage unknown.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R861_ThunderbirdZipGetThenBashTlsRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R865 — Curl CMD-file GET followed by cmd-attributed public SYN</strong> · Medium</summary>

- **Description:** Curl-attributed HTTP/80 .cmd GET precedes cmd-attributed TCP/8443 SYN to another public peer within 60s; file execution, shell ancestry and download success unknown.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R865_CurlCmdGetThenCmdPublicSynRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R877 — Docker remote create and start HTTP API requests</strong> · Medium</summary>

- **Description:** Same private client sends Docker HTTP/2375 POST /containers/create then a POST /containers/{id}/start to the same daemon within 60s; no image policy, privileged flags or successful deployment is verified.
- **Category:** Execution
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R877_DockerApiCreateThenStartRequestRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Exfiltration: 13 rules

<details>
<summary>Choose a rule from 13 Exfiltration entries</summary>

<details>
<summary><strong>R008 — Exfiltration</strong> · High</summary>

- **Description:** Possible data exfiltration behavior
- **Category:** Exfiltration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R008_ExfiltrationRule.cs)
- **Detailed evidence and test scenarios:** [006-010](batches/RULE_BATCH_006-010.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R036 — Heavy Egress to Single External Host</strong> · High</summary>

- **Description:** Heavy egress to one external host
- **Category:** Exfiltration
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R036_HeavyEgressToSingleExternalHostRule.cs)
- **Detailed evidence and test scenarios:** [036-040](batches/RULE_BATCH_036-040.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R849 — Python same-peer uniform outbound TCP payload cadence</strong> · Medium</summary>

- **Description:** Four Python-attributed public TCP/4444 payloads of near-equal size at 2-6 second spacing; no file, exfiltration content or completed transfer inferred.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R849_PythonUniformOutboundPayloadCadenceRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R852 — PowerShell Dropbox-content TLS payload burst</strong> · Medium</summary>

- **Description:** Five same-PID outbound PowerShell TCP/443 payload packets of &gt;=1200 bytes to content.dropboxapi.com SNI in 30s; no decrypted upload, account identity, file or exfiltration established.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R852_PowershellCloudTlsPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R854 — PowerShell public SYNs tagged Wi-Fi and Cellular</strong> · Medium</summary>

- **Description:** Same local PowerShell PID has typed public TCP/8443 SYNs tagged Wi-Fi and Cellular within 90s; labels are untrusted enrichment, not physical interface or exfiltration proof.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R854_PowershellAlternateNetworkTypeSynRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R855 — Hostd-attributed public HTTP/8080 POST burst</strong> · Medium</summary>

- **Description:** Five hostd/vpxa-attributed cleartext POST packets to one public TCP/8080 peer in 20s; no ESXi provenance, FTP, transferred file, unauthorized policy or completed exfiltration established.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R855_HostdExternalHttpPostBurstRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R858 — Hostd-attributed public TLS/9443 large burst</strong> · Medium</summary>

- **Description:** Five hostd-attributed TLS/9443 packets to one public peer in 30s and &gt;=9000 packet-payload bytes; ESXi role, data transfer and exfiltration unknown.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R858_HostdPublicTls9443BurstRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R863 — Rsync-attributed public TCP/873 payload burst</strong> · Medium</summary>

- **Description:** Five rsync-attributed TCP/873 packets to one public peer within 30s have at least 10000 payload bytes; file read and successful sync not observed.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R863_RsyncPublic873PayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R904 — Curl public binary HTTP PUT request</strong> · Medium</summary>

- **Description:** Local curl attribution and a public cleartext HTTP PUT with exact application/octet-stream content-type, typed request and at least 512 transport payload bytes; file contents, upload completion and exfiltration are unknown.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R904_CurlPublicBinaryHttpPutRule.cs)
- **Detailed evidence and test scenarios:** [901-905](batches/RULE_BATCH_901-905.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R938 — Ollama public embedding API HTTP POST</strong> · Medium</summary>

- **Description:** Ollama-attributed cleartext public POST to /api/embed or /api/embeddings on TCP/11434 with at least 512 transport bytes. Input contents, sensitive data, AI policy and exfiltration are unknown.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R938_OllamaPublicEmbeddingHttpPostRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R939 — Curl public HTTP POST cadence</strong> · Medium</summary>

- **Description:** Same private curl PID and public HTTP host/path sends four POST records of 512–4096 transport bytes at 5–20s intervals within 65s. Scheduled task, file contents and transfer completion are unknown.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R939_CurlPublicRepeatedUploadCadenceRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R945 — Osascript public Discord webhook HTTP POST</strong> · Medium</summary>

- **Description:** Osascript-attributed cleartext public HTTP POST to Discord webhook path with exact Discord host. Webhook token, content, authorization and C2 are unknown.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R945_OsascriptPublicDiscordWebhookPostRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R964 — OpenSSL public TLS/8443 then same-peer TLS/443</strong> · Medium</summary>

- **Description:** Same OpenSSL PID sends TLS data to public TCP/8443 then TCP/443 at the same peer. File encryption, symmetric key use, content, operating system and exfiltration are unknown.
- **Category:** Exfiltration
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R964_OpensslPublic8443ThenSamePeer443TlsRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### ExfiltrationAdvanced: 39 rules

<details>
<summary>Choose a rule from 39 ExfiltrationAdvanced entries</summary>

<details>
<summary><strong>R243 — Large Outbound Archive Transfer</strong> · High</summary>

- **Description:** Detects large outbound archive transfers only when the transfer is external, archive-like, and not explained by approved sync or backup clients.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R243_LargeOutboundArchiveTransferRule.cs)
- **Detailed evidence and test scenarios:** [241-245](batches/RULE_BATCH_241-245.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R244 — Database Dump Filename Transfer</strong> · Critical</summary>

- **Description:** Detects outbound transfers whose observable name/path strongly resembles a database dump or backup artifact.
- **Category:** ExfiltrationAdvanced
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R244_DatabaseDumpFilenameTransferRule.cs)
- **Detailed evidence and test scenarios:** [241-245](batches/RULE_BATCH_241-245.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R245 — Sensitive File Extension Upload</strong> · High</summary>

- **Description:** Detects external upload of files whose name, extension, or metadata indicates credentials, keys, secrets, or sensitive exports.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R245_SensitiveFileExtensionUploadRule.cs)
- **Detailed evidence and test scenarios:** [241-245](batches/RULE_BATCH_241-245.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R246 — Source Code Archive Upload</strong> · High</summary>

- **Description:** Detects external upload of archive artifacts whose observable name/path suggests source code or repository content.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R246_SourceCodeArchiveUploadRule.cs)
- **Detailed evidence and test scenarios:** [246-250](batches/RULE_BATCH_246-250.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R247 — SSH SCP High Volume Egress</strong> · High</summary>

- **Description:** Detects high-volume SSH/SCP/SFTP egress from internal hosts to external targets with process or protocol evidence.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R247_SshScpHighVolumeEgressRule.cs)
- **Detailed evidence and test scenarios:** [246-250](batches/RULE_BATCH_246-250.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R248 — FTP Upload To External Host</strong> · High</summary>

- **Description:** Detects FTP upload semantics from an internal source to an external host, not merely any FTP control connection.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R248_FtpUploadToExternalHostRule.cs)
- **Detailed evidence and test scenarios:** [246-250](batches/RULE_BATCH_246-250.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R249 — SMB Upload To External Host</strong> · Critical</summary>

- **Description:** Detects SMB write/upload behavior crossing to an external target, avoiding generic port-445 noise.
- **Category:** ExfiltrationAdvanced
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R249_SmbUploadToExternalHostRule.cs)
- **Detailed evidence and test scenarios:** [246-250](batches/RULE_BATCH_246-250.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R250 — Large HTTP POST To IP Literal</strong> · High</summary>

- **Description:** Detects large HTTP upload requests to raw IP-literal external targets, suppressing normal host-based SaaS traffic.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R250_LargeHttpPostToIpLiteralRule.cs)
- **Detailed evidence and test scenarios:** [246-250](batches/RULE_BATCH_246-250.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R251 — Multipart Upload To Unknown Domain</strong> · High</summary>

- **Description:** Detects multipart/form-data uploads to first-seen external domains outside known sanctioned cloud roots.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R251_MultipartUploadToUnknownDomainRule.cs)
- **Detailed evidence and test scenarios:** [251-255](batches/RULE_BATCH_251-255.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R252 — High Entropy Outbound URI Path</strong> · Medium</summary>

- **Description:** Detects outbound HTTP requests with long high-entropy URI path tokens only when paired with upload/automation/volume evidence.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R252_HighEntropyOutboundUriPathRule.cs)
- **Detailed evidence and test scenarios:** [251-255](batches/RULE_BATCH_251-255.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R253 — Base64 Blob In HTTP POST</strong> · High</summary>

- **Description:** Detects large base64-like blobs in outbound HTTP upload requests with automation or external unknown-destination support.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R253_Base64BlobInHttpPostRule.cs)
- **Detailed evidence and test scenarios:** [251-255](batches/RULE_BATCH_251-255.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R254 — Repeated Small Chunk Uploads</strong> · High</summary>

- **Description:** Detects repeated small outbound upload chunks to the same external target within a short window.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R254_RepeatedSmallChunkUploadsRule.cs)
- **Detailed evidence and test scenarios:** [251-255](batches/RULE_BATCH_251-255.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R255 — Off-Hours Bulk Egress Indicator</strong> · Medium</summary>

- **Description:** Detects bulk outbound transfer during off-hours only when additional exfil indicators are present.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R255_OffHoursBulkEgressIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [251-255](batches/RULE_BATCH_251-255.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R256 — Internal Data Staging Server Behavior</strong> · High</summary>

- **Description:** Detects internal host-to-host staging behavior when archive/dump/sensitive indicators and repeated collection volume are visible.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R256_InternalDataStagingServerBehaviorRule.cs)
- **Detailed evidence and test scenarios:** [256-260](batches/RULE_BATCH_256-260.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R257 — Exfiltration After Credential Alert Chain</strong> · Critical</summary>

- **Description:** Detects exfiltration-like egress when the same record/source carries credential-compromise context or recent credential-alert indicators.
- **Category:** ExfiltrationAdvanced
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R257_ExfiltrationAfterCredentialAlertChainRule.cs)
- **Detailed evidence and test scenarios:** [256-260](batches/RULE_BATCH_256-260.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R554 — SMB2 Write Requests Followed by External FTP Upload Command</strong> · High</summary>

- **Description:** A private IPv4 source sends SMB2 WRITE request shapes to two other private /24 networks, then a parsed FTP STOR/APPE command to a public IPv4 server within two minutes; no transfer outcome is known.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R554_Smb2WriteThenExternalFtpUploadRule.cs)
- **Detailed evidence and test scenarios:** [554-554](batches/RULE_BATCH_554-554.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R555 — External FTP Upload Command Subnet Fanout</strong> · High</summary>

- **Description:** A private IPv4 client sends parser-classified FTP STOR/APPE requests to three different public /24s in five minutes; server acceptance and data transfer are unknown.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R555_ExternalFtpUploadCommandSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [555-555](batches/RULE_BATCH_555-555.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R565 — Default HTTP Admin Credential Attempt Then FTP Callback</strong> · High</summary>

- **Description:** A public peer sends a known-default HTTP Basic admin request to a private host; within two minutes that exact private host sends an FTP STOR/APPE command back to the same public peer. No authentication or transfer outcome is established.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R565_DefaultBasicAdminThenFtpCallbackRule.cs)
- **Detailed evidence and test scenarios:** [565-565](batches/RULE_BATCH_565-565.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R569 — FTP Upload Attempt Then Default HTTP Admin Credential Attempt</strong> · High</summary>

- **Description:** A private host sends a parsed FTP STOR/APPE command to a public peer; within two minutes that peer attempts known-default HTTP Basic authentication on the same private host. No authentication or transfer outcome is established.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R569_FtpUploadAttemptThenDefaultBasicAdminRule.cs)
- **Detailed evidence and test scenarios:** [569-569](batches/RULE_BATCH_569-569.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R584 — Outbound SMB2 WRITE Request Public Subnet Fanout</strong> · High</summary>

- **Description:** A private client sends bounded SMB2 WRITE request shapes to three distinct public /24 networks on TCP/445 in five minutes; neither writes nor transfers are confirmed.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R584_OutboundSmb2WriteSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [580-584](batches/RULE_BATCH_580-584.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R652 — Script host FTP upload command to public endpoint</strong> · High</summary>

- **Description:** Script host FTP upload command to public endpoint. R248 generic FTP STOR/appe; this requires correlated local script-host process/PID and parsed request.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R652_ScriptHostFtpExternalUploadRequestRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R658 — Regular-size outbound TCP payload sequence from an attributed process</strong> · Low</summary>

- **Description:** Regular-size outbound TCP payload sequence from an attributed process. R254 counts repeated declared HTTP uploads; this matches four non-HTTP TCP payload observations with constrained lengths and spacing, without transfer claims.
- **Category:** ExfiltrationAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R658_UniformIntervalOutboundProcessTcpPayloadSequenceRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R663 — FTP STOR then APPE requests to same external peer</strong> · Medium</summary>

- **Description:** FTP STOR then APPE requests to same external peer. R248 detects a single STOR/APPEND command and R652 requires script-host identity; this candidate requires both distinct request types in order.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R663_ExternalFtpStorAppeRequestPairRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R671 — Eight large raw TCP payload observations from an attributed script process</strong> · Low</summary>

- **Description:** Eight large raw TCP payload observations from an attributed script process. Observed packet payload length is not directional application bytes, delivery, data content or demonstrated junk traffic.
- **Category:** ExfiltrationAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R671_ScriptProcessLargeRawTcpPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R715 — Private client TFTP request followed by public-server transfer reply</strong> · Low</summary>

- **Description:** Private client to public server: capture-attested TFTP RRQ or WRQ followed by its exact first DATA block 1 or ACK block 0 within 30 seconds. No transfer completion, file identity, firmware change, authorization or compromise established.
- **Category:** ExfiltrationAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R715_PrivateClientPublicTftpExchangeRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R718 — PowerShell or Office process TLS payload burst to cloud storage</strong> · Medium</summary>

- **Description:** A PowerShell or Office process is associated with four substantial TLS payload observations to a known cloud-storage SNI within two minutes. Packet lengths are not unique transferred bytes and do not prove an upload, file access, authentication, or exfiltration.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R718_UnusualProcessCloudStorageTlsPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R719 — PowerShell process raw SMB-port payload burst to public host</strong> · Medium</summary>

- **Description:** A PowerShell process produces three raw TCP payload observations to a public TCP/445 peer within two minutes. SMB authentication, share access, file transfer, unique byte counts, and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R719_PowerShellExternalSmbPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R726 — ESXi management process external TLS payload burst</strong> · Medium</summary>

- **Description:** hostd, vpxa, or vmx is associated with four substantial TLS/443 payload observations to one public peer within two minutes. Packet lengths are not unique transferred bytes and do not prove datastore reads, uploads, web-service use, exfiltration, or compromise.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R726_EsxiManagementProcessExternalTlsBurstRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R734 — macOS non-browser process external TLS payload burst</strong> · Low</summary>

- **Description:** A non-browser macOS scripting/utility process produces four substantial TLS/443 payload observations to one public peer within two minutes. Known text-storage, code-repository and cloud-storage service families are excluded to avoid overlap. File reads, compression, unique transfer bytes and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R734_MacNonBrowserExternalTlsPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R736 — Linux non-browser process external TLS payload burst</strong> · Medium</summary>

- **Description:** curl, wget, Python, rsync, scp, sftp, or rclone is associated with four substantial TLS/443 payload observations to one public peer within two minutes. File reads, archive creation, unique TCP bytes, upload semantics and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R736_LinuxNonBrowserTlsPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R737 — Linux CLI/script large cleartext HTTP upload-shaped burst</strong> · Medium</summary>

- **Description:** curl, wget, Python, or Python3 is associated with four substantial cleartext HTTP POST/PUT packet observations to one public peer within two minutes. Local file access, request-body reconstruction, response status, delivered bytes and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R737_LinuxCliLargeHttpPostBurstRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R738 — Linux transfer-tool recurrent outbound payload cadence</strong> · Low</summary>

- **Description:** rsync, scp, sftp, rclone, curl, wget, or Python is associated with three similarly sized outbound TCP payload observations to the same public peer at regular 20–70 second intervals. Cron scheduling, user identity, file contents, transfer completion and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R738_LinuxRecurrentTransferCadenceRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R740 — macOS utility cleartext HTTP upload-shaped burst</strong> · Medium</summary>

- **Description:** osascript, Microsoft Word, Microsoft Excel, or Preview is associated with four substantial cleartext HTTP POST/PUT packet observations to one public peer within two minutes. Local document access, request-body reconstruction, response, delivered bytes and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R740_MacOsUtilityLargeHttpPostBurstRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R746 — ESXi management-process nonstandard-port TLS payload burst</strong> · Medium</summary>

- **Description:** hostd, vpxa, or vmx is associated with four substantial TLS payload observations to one public peer on a bounded nonstandard TLS port within two minutes. Encryption algorithm, file source, unique TCP bytes, upload semantics and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R746_EsxiManagementProcessNonstandardTlsBurstRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R747 — Windows archive-tool external TLS payload burst</strong> · Medium</summary>

- **Description:** 7-Zip or WinRAR process attribution is associated with four substantial TLS/443 payload observations to one public peer within two minutes. Archive creation, local file access, destination novelty, request semantics and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R747_WindowsArchiveToolExternalTlsBurstRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R748 — Linux crypto-tool uncommon-port payload burst</strong> · Medium</summary>

- **Description:** openssl, gpg, gpg2, or age is associated with four substantial raw TCP payload observations to one public uncommon port within two minutes. Encryption invocation, key material, file source, delivered bytes and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R748_LinuxCryptoToolUncommonPortPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R749 — ESXi-style shell tool external FTP upload request</strong> · High</summary>

- **Description:** busybox, curl, wget, ftpput, or lftp is associated with a parsed FTP STOR/APPE upload command to a public endpoint. Shell history, source file, server response, data-channel delivery and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R749_EsxiShellToolExternalFtpUploadRequestRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R750 — macOS-characteristic process cloud-storage TLS payload burst</strong> · Medium</summary>

- **Description:** osascript, Microsoft Word, Microsoft Excel, or Preview is associated with four substantial TLS/443 payload observations to a known cloud-storage SNI within two minutes. Local file reads, xattr changes, upload semantics, unique bytes and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R750_MacProcessCloudStorageTlsPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R753 — osascript recurrent external TLS cadence</strong> · Low</summary>

- **Description:** osascript is associated with three similarly sized TLS/443 payload observations to one public peer at 30–90 second intervals. LaunchAgent scheduling, user identity, local file access, request content and exfiltration are not observed.
- **Category:** ExfiltrationAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R753_OsascriptExternalTlsRecurrentCadenceRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### GeoIP: 1 rules

<details>
<summary>Choose a rule from 1 GeoIP entries</summary>

<details>
<summary><strong>R010 — GeoIP</strong> · Low</summary>

- **Description:** Destination country or geo-policy anomaly
- **Category:** GeoIP
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R010_GeoIpRule.cs)
- **Detailed evidence and test scenarios:** [006-010](batches/RULE_BATCH_006-010.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### HTTP: 7 rules

<details>
<summary>Choose a rule from 7 HTTP entries</summary>

<details>
<summary><strong>R018 — HTTP to IP Literal Without Host Header</strong> · Medium</summary>

- **Description:** HTTP request to IP literal without Host header
- **Category:** HTTP
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R018_HttpToIpLiteralWithoutHostHeaderRule.cs)
- **Detailed evidence and test scenarios:** [016-020](batches/RULE_BATCH_016-020.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R019 — Encoded / Long URI</strong> · Medium</summary>

- **Description:** Encoded or unusually long URI
- **Category:** HTTP
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R019_EncodedLongUriRule.cs)
- **Detailed evidence and test scenarios:** [016-020](batches/RULE_BATCH_016-020.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R032 — Suspicious / Empty HTTP User-Agent</strong> · Medium</summary>

- **Description:** Suspicious or empty User-Agent
- **Category:** HTTP
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R032_SuspiciousEmptyHttpUserAgentRule.cs)
- **Detailed evidence and test scenarios:** [031-035](batches/RULE_BATCH_031-035.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R043 — SNI / HTTP Host Mismatch</strong> · Medium</summary>

- **Description:** SNI and HTTP Host mismatch
- **Category:** HTTP
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R043_SniHttpHostMismatchRule.cs)
- **Detailed evidence and test scenarios:** [041-045](batches/RULE_BATCH_041-045.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R044 — Unusual HTTP Methods to Internet</strong> · Medium</summary>

- **Description:** Unusual HTTP methods to internet
- **Category:** HTTP
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R044_UnusualHttpMethodsToInternetRule.cs)
- **Detailed evidence and test scenarios:** [041-045](batches/RULE_BATCH_041-045.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R045 — Sparse-Header POST to Internet</strong> · Medium</summary>

- **Description:** Sparse-header POST to internet
- **Category:** HTTP
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R045_SparseHeaderPostToInternetRule.cs)
- **Detailed evidence and test scenarios:** [041-045](batches/RULE_BATCH_041-045.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R047 — HTTP Basic Auth to IP Literal</strong> · Medium</summary>

- **Description:** HTTP Basic Auth to IP literal
- **Category:** HTTP
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R047_HttpBasicAuthToIpLiteralRule.cs)
- **Detailed evidence and test scenarios:** [046-050](batches/RULE_BATCH_046-050.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### HttpApi: 90 rules

<details>
<summary>Choose a rule from 90 HttpApi entries</summary>

<details>
<summary><strong>R153 — GraphQL Introspection Query</strong> · Medium</summary>

- **Description:** Detects explicit GraphQL introspection requests on cross-boundary HTTP flows instead of relying on loose GraphQL text alone.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R153_GraphqlIntrospectionQueryRule.cs)
- **Detailed evidence and test scenarios:** [151-155](batches/RULE_BATCH_151-155.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R154 — GraphQL Batching Abuse</strong> · Medium</summary>

- **Description:** Detects repeated GraphQL batch-style requests to the same endpoint instead of alerting on generic GraphQL traffic.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R154_GraphqlBatchingAbuseRule.cs)
- **Detailed evidence and test scenarios:** [151-155](batches/RULE_BATCH_151-155.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R155 — REST API Enumeration Burst</strong> · Medium</summary>

- **Description:** Detects cross-boundary bursts of distinct REST API resource requests instead of alerting on isolated API calls.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R155_RestApiEnumerationBurstRule.cs)
- **Detailed evidence and test scenarios:** [151-155](batches/RULE_BATCH_151-155.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R156 — JWT None Algorithm Indicator</strong> · High</summary>

- **Description:** Detects JWT material whose decoded header explicitly uses the none algorithm instead of loose alg:none text matching.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R156_JwtNoneAlgorithmIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [156-160](batches/RULE_BATCH_156-160.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R157 — JWT In URL Query</strong> · Medium</summary>

- **Description:** Detects JWT-like bearer material exposed in URL query parameters instead of broad token substring matching.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R157_JwtInUrlQueryRule.cs)
- **Detailed evidence and test scenarios:** [156-160](batches/RULE_BATCH_156-160.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R158 — Swagger OpenAPI Exposure Probe</strong> · Medium</summary>

- **Description:** Detects cross-boundary access to Swagger or OpenAPI discovery endpoints rather than generic documentation browsing.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R158_SwaggerOpenapiExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [156-160](batches/RULE_BATCH_156-160.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R159 — Spring Actuator Exposure Probe</strong> · High</summary>

- **Description:** Detects cross-boundary probes to sensitive Spring Actuator endpoints while suppressing benign health and info checks.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R159_SpringActuatorExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [156-160](batches/RULE_BATCH_156-160.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R160 — Kubernetes API Probe</strong> · High</summary>

- **Description:** Detects cross-boundary requests to concrete Kubernetes API paths instead of generic /api traffic.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R160_KubernetesApiProbeRule.cs)
- **Detailed evidence and test scenarios:** [156-160](batches/RULE_BATCH_156-160.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R161 — Docker API TCP Exposure Probe</strong> · High</summary>

- **Description:** Detects cross-boundary requests to Docker daemon API paths on Docker-like hosts or ports instead of loose /version matching.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R161_DockerApiTcpExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [161-165](batches/RULE_BATCH_161-165.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R162 — Redis Memcached Web Probe</strong> · Medium</summary>

- **Description:** Detects cross-boundary web probes aimed at Redis or Memcached administration surfaces instead of generic stats endpoints.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R162_RedisMemcachedWebProbeRule.cs)
- **Detailed evidence and test scenarios:** [161-165](batches/RULE_BATCH_161-165.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R163 — SSRF Metadata Service Probe</strong> · Critical</summary>

- **Description:** Observes cloud metadata credential requests from non-standard callers; SSRF requires separate causal evidence.
- **Category:** HttpApi
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R163_SsrfMetadataServiceProbeRule.cs)
- **Detailed evidence and test scenarios:** [161-165](batches/RULE_BATCH_161-165.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R164 — Open Redirect Parameter Abuse</strong> · Medium</summary>

- **Description:** Detects redirect-style query parameters that point to suspicious external or internal targets instead of matching every redirect_uri string.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R164_OpenRedirectParameterAbuseRule.cs)
- **Detailed evidence and test scenarios:** [161-165](batches/RULE_BATCH_161-165.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R165 — PHPInfo Exposure Probe</strong> · Low</summary>

- **Description:** Detects cross-boundary access to concrete phpinfo exposure paths instead of generic info pages.
- **Category:** HttpApi
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R165_PhpinfoExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [161-165](batches/RULE_BATCH_161-165.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R166 — Environment File Secret Probe</strong> · High</summary>

- **Description:** Detects cross-boundary requests to concrete environment or secret-bearing file paths instead of broad config.json matching.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R166_EnvironmentFileSecretProbeRule.cs)
- **Detailed evidence and test scenarios:** [166-170](batches/RULE_BATCH_166-170.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R167 — Git Directory Exposure Probe</strong> · High</summary>

- **Description:** Detects cross-boundary requests to exposed .git internals instead of broad git substring matches.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R167_GitDirectoryExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [166-170](batches/RULE_BATCH_166-170.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R168 — Backup Archive Download Probe</strong> · Medium</summary>

- **Description:** Detects cross-boundary requests for filenames that strongly resemble database or site backups instead of every archive download.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R168_BackupArchiveDownloadProbeRule.cs)
- **Detailed evidence and test scenarios:** [166-170](batches/RULE_BATCH_166-170.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R169 — Admin Login Brute Indicator</strong> · Medium</summary>

- **Description:** Detects repeated authentication failures against admin login paths instead of every admin page request.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R169_AdminLoginBruteIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [166-170](batches/RULE_BATCH_166-170.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R170 — XXE Payload Indicator</strong> · High</summary>

- **Description:** Detects XML or SOAP requests with explicit XXE payload indicators instead of matching raw xxe text alone.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R170_XxePayloadIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [166-170](batches/RULE_BATCH_166-170.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R171 — SOAP Action Exploit Pattern</strong> · Medium</summary>

- **Description:** Detects SOAP requests whose SOAPAction header carries explicit exploit-oriented method names instead of alerting on every SOAP envelope.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R171_SoapActionExploitPatternRule.cs)
- **Detailed evidence and test scenarios:** [171-175](batches/RULE_BATCH_171-175.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R172 — Scanner User Agent With Browser Claim Mismatch</strong> · Low</summary>

- **Description:** Detects HTTP user agents that simultaneously identify as known scanners and as browsers, rather than every scanner user agent.
- **Category:** HttpApi
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R172_ScannerUserAgentWithBrowserClaimMismatchRule.cs)
- **Detailed evidence and test scenarios:** [171-175](batches/RULE_BATCH_171-175.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R173 — Suspicious CORS Preflight To Admin API</strong> · Medium</summary>

- **Description:** Detects cross-boundary CORS preflights to admin-like APIs with sensitive requested headers instead of every OPTIONS request.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R173_SuspiciousCorsPreflightToAdminApiRule.cs)
- **Detailed evidence and test scenarios:** [171-175](batches/RULE_BATCH_171-175.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R174 — WebDAV Method Abuse</strong> · Medium</summary>

- **Description:** Detects suspicious WebDAV verbs and Depth: infinity style probes instead of every WebDAV-related request.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R174_WebdavMethodAbuseRule.cs)
- **Detailed evidence and test scenarios:** [171-175](batches/RULE_BATCH_171-175.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R175 — HTTP Request Smuggling Indicator</strong> · High</summary>

- **Description:** Detects concrete conflicting HTTP framing headers such as CL+TE or multiple Content-Length values instead of matching the word chunked alone.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R175_HttpRequestSmugglingIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [171-175](batches/RULE_BATCH_171-175.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R176 — Host Header Injection Indicator</strong> · Medium</summary>

- **Description:** Detects Host or forwarded-host headers that target internal or mismatched hosts instead of alerting on every proxy-related header.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R176_HostHeaderInjectionIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [176-180](batches/RULE_BATCH_176-180.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R177 — High-Risk File Upload Extension</strong> · High</summary>

- **Description:** Detects HTTP upload workflows carrying executable or web-shell style filenames instead of every multipart request.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R177_HighRiskFileUploadExtensionRule.cs)
- **Detailed evidence and test scenarios:** [176-180](batches/RULE_BATCH_176-180.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R586 — WordPress wp2shell plugin access request</strong> · High</summary>

- **Description:** Specific wp2shell plugin path requested; access is not evidence of successful exploitation.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R586_Wp2ShellPluginAccessRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R587 — ScreenConnect SetupWizard path request</strong> · High</summary>

- **Description:** GET request uses SetupWizard.aspx trailing path segment; bypass is unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R587_ScreenConnectSetupWizardPathRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R588 — SolarWinds SUPERNOVA handler request</strong> · High</summary>

- **Description:** LogoImageHandler.ashx with clazz query marker; webshell presence unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R588_SolarWindsSupernovaHandlerRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R589 — WebLogic keystore script request</strong> · High</summary>

- **Description:** Script-like resource requested under WebLogic config/keystore; dropped webshell unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R589_WebLogicKeystoreScriptRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R590 — Rejetto HFS search injection request</strong> · High</summary>

- **Description:** HFS search marker combined with process-command string; execution unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R590_RejettoHfsSearchPayloadRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R591 — ADSelfService suspicious endpoint request</strong> · High</summary>

- **Description:** Specific ADSelfService API/help endpoint observed; exploitation unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R591_AdSelfServiceSuspiciousEndpointRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R592 — DEWMODE webshell-shaped query request</strong> · High</summary>

- **Description:** HTML resource with both dwn and fn query controls; webshell presence unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R592_DewmodeWebshellQueryRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R593 — Apache Spark doAs backtick request</strong> · High</summary>

- **Description:** Backtick substitution in doAs request parameter; command execution unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R593_ApacheSparkDoAsBacktickRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R594 — Bitbucket archive exec-prefix request</strong> · High</summary>

- **Description:** Bitbucket archive API prefix contains NUL exec marker; execution unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R594_BitbucketArchiveExecPrefixRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R595 — Grafana plugin traversal request</strong> · High</summary>

- **Description:** Grafana plugin path with repeated dot-dot segments; file disclosure unproven.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R595_GrafanaPluginTraversalRequestRule.cs)
- **Detailed evidence and test scenarios:** [586-595](batches/RULE_BATCH_586-595.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R596 — SonicWall Jarrewrite Suspicious User Agent Request</strong> · High</summary>

- **Description:** Jarrewrite endpoint accompanied by Shellshock-like User-Agent bytes; request observed only.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R596_SonicWallJarrewriteAbuseRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R597 — MODx tvs.php class_key traversal request</strong> · High</summary>

- **Description:** MODx manager tvs.php class_key parameter with traversal to Windows win.ini and encoded NUL; response unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R597_ModxTvsClassKeyTraversalRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R598 — Windows local filesystem path in HTTP query</strong> · High</summary>

- **Description:** HTTP query contains a Windows local file path literal (Users, Program Files or Windows), with no claim of exfiltration or disclosure.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R598_WindowsLocalPathInHttpQueryRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R599 — Arcadyan apply_abstract.cgi encoded traversal request</strong> · High</summary>

- **Description:** Arcadyan router config endpoint and encoded parent-path traversal observed together; outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R599_ArcadyanAbstractConfigTraversalRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R600 — Exchange HAFNIUM themes-resource POST request</strong> · High</summary>

- **Description:** HTTP POST to the abnormal /owa/auth/Current/themes/resources/ subtree; intent/outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R600_ExchangeHafniumThemesResourcePostRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R601 — ReGeorg-like headerless control query POST</strong> · High</summary>

- **Description:** POST with known ReGeorg command parameters, absent User-Agent and captured header summary without Referer; not proof of a webshell.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R601_ReGeorgHeaderlessControlQueryRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R602 — SolarWinds Orion resource API bypass-shaped request</strong> · High</summary>

- **Description:** Suspicious Orion /SolarWinds/ API resource route using resource-handler path while excluding ordinary localization requests.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R602_SolarWindsOrionResourceAuthBypassRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R603 — WebLogic JNDI binding handle LDAP URI request</strong> · High</summary>

- **Description:** WebLogic GET query includes JndiBindingHandle, LDAP reference and AdminServer; JNDI lookup outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R603_WebLogicJndiBindingLdapRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R604 — Exchange ECP or OWA VIEWSTATE-bearing GET</strong> · High</summary>

- **Description:** GET against Exchange ECP/OWA path containing __VIEWSTATE query parameter; no deserialization result inferred.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R604_ExchangeViewStateQueryRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R605 — Confluence upload.action filename traversal POST</strong> · High</summary>

- **Description:** Confluence upload.action POST with multi-level filename parameter traversal; file-write outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R605_ConfluenceUploadFilenameTraversalRequestRule.cs)
- **Detailed evidence and test scenarios:** [596-605](batches/RULE_BATCH_596-605.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R606 — Pulse Guacamole query-embedded request</strong> · High</summary>

- **Description:** Parser-backed HTTP request shape only; outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R606_PulseGuacamoleQueryRequestRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R607 — Kemp LoadMaster API enable GET</strong> · High</summary>

- **Description:** Parser-backed HTTP request shape only; outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R607_KempLoadMasterApiEnableGetRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R608 — Exchange mastermailbox PowerShell SSRF request</strong> · High</summary>

- **Description:** Parser-backed HTTP request shape only; outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R608_ExchangeMastermailboxPowerShellRequestRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R609 — Exchange encoded-at PowerShell SSRF request</strong> · High</summary>

- **Description:** Parser-backed HTTP request shape only; outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R609_ExchangeEncodedAtPowerShellRequestRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R610 — Exchange OWA calendar endpoint POST</strong> · High</summary>

- **Description:** Parser-backed HTTP request shape only; outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R610_ExchangeOwaCalendarEndpointPostRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R611 — Fortinet SAML remoteserver POST with anomalous Referer</strong> · High</summary>

- **Description:** Parser-backed HTTP request shape only; outcome unknown.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R611_FortinetSamlRemoteserverPostRule.cs)
- **Detailed evidence and test scenarios:** [606-615](batches/RULE_BATCH_606-615.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R616 — Exchange ECP Virtual Directory Reset Request</strong> · High</summary>

- **Description:** HTTP request: specific workbook candidate, detection only; The Sigma source requires HTTP 200 and machine-account username ending $, neither is established by the packet record.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R616_ExchangeEcpVirtualDirectoryResetRequestRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R617 — SolarWinds SUPERNOVA LogoImageHandler Clazz Request</strong> · High</summary>

- **Description:** HTTP request: specific workbook candidate, detection only; Cannot observe original Sigma branch based solely on HTTP 500; only joint logoimagehandler+clazz URI is detected.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R617_SolarWindsSupernovaClazzRequestRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R618 — Exchange ProxyShell Autodiscover Back-End Request</strong> · High</summary>

- **Description:** HTTP request: specific workbook candidate, detection only; Workbook marks 200/301 response as success; rule recognizes only an HTTP request, without validating response.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R618_ExchangeProxyShellAutodiscoverBackendRequestRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R619 — Encoded Java Expression in HTTP Request URI</strong> · Medium</summary>

- **Description:** HTTP request: specific workbook candidate, detection only; Headers, HTTP status and server execution unavailable; may overlap general injection alerts but distinct exact encoded selectors.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R619_EncodedJavaExpressionUriRequestRule.cs)
- **Detailed evidence and test scenarios:** [616-625](batches/RULE_BATCH_616-625.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R626 — WordPress wp2shell plugin HTTP access</strong> · High</summary>

- **Description:** Original R2094; R087 generic webshell upload; here a particular wp2shell plugin access request, not a proved webshell installation. Only observable packet fields, no asserted outcome.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R626_WordPressWp2shellPluginRequestRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R627 — WebLogic keystore webshell-like URI request</strong> · High</summary>

- **Description:** Original R2286; R087 webshell upload; here direct WebLogic keystore path request without upload inference. Only observable packet fields, no asserted outcome.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R627_WebLogicKeystoreJspRequestRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R628 — Exchange ProxyToken RulesEditor NewObject request</strong> · High</summary>

- **Description:** Original R3031; R319 generic ECP probe, R616 ECP SetObject Reset; this matches a separate RulesEditor NewObject request. Only observable packet fields, no asserted outcome.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R628_ExchangeProxyTokenRulesEditorRequestRule.cs)
- **Detailed evidence and test scenarios:** [626-635](batches/RULE_BATCH_626-635.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R636 — OMIGOD-like unauthenticated WSMan POST attempt</strong> · High</summary>

- **Description:** OMIGOD-like unauthenticated WSMan POST attempt. Observed evidence only; HTTP 200, server command and successful exploit are unavailable; absence of an Authorization header in the capture summary is not authenticated absence.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R636_OmigodUnauthenticatedWsmanPostRequestRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R642 — Script interpreter HTTP POST with browser-like user agent</strong> · Medium</summary>

- **Description:** Script interpreter HTTP POST with browser-like user agent. Observed evidence only; No process parent lineage or API-caller provenance; a browser-like User-Agent is not proof of spoofing and the local PID may be untrusted.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R642_ScriptProcessBrowserAgentHttpPostRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R645 — Cleartext login-form POST to a punycode HTTP host</strong> · Low</summary>

- **Description:** Cleartext login-form POST to a punycode HTTP host. Observed evidence only; Cannot inspect credential contents, verify domain mimicry or infer phishing; legitimate internationalized domains and tests may match.
- **Category:** HttpApi
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R645_PunycodeLoginFormPostExposureRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R646 — HTTP firmware upload request to device management endpoint</strong> · High</summary>

- **Description:** HTTP firmware upload request to device management endpoint. R236 detects firmware GET/download; this requires a POST with upload path and binary content-type. No change outcome.
- **Category:** HttpApi
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R646_DeviceFirmwareHttpUploadAttemptRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R651 — External CMS content-save POST request observed</strong> · Medium</summary>

- **Description:** External CMS content-save POST request observed. R087 monitors webshell upload, R169 admin login; this requires an explicit content-editor save POST from public to private.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R651_ExternalCmsContentSavePostAttemptRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R664 — Script process GET carrying a long encoded query to public IP literal</strong> · Medium</summary>

- **Description:** Script process GET carrying a long encoded query to public IP literal. R019 is generic encoded/long URI, while this requires a script process/PID, exact IP literal HTTP host, GET and explicit long URL-safe query parameter.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R664_ScriptProcessLongEncodedHttpGetToIpLiteralRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R666 — Specific SQL injection token in cleartext HTTP GET URI</strong> · Medium</summary>

- **Description:** Specific SQL injection token in cleartext HTTP GET URI. Only observed URI bytes, no database execution, returned data, or HTTP status.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R666_SpecificSqlInjectionGetUriRequestRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R668 — Rundll32-associated HTTP API POST to a public host</strong> · Medium</summary>

- **Description:** Rundll32-associated HTTP API POST to a public host. Process-to-flow PID attribution is best effort; HTTP request is not C2 or delivery evidence.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R668_Rundll32CleartextApiPostPublicRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R672 — PowerShell POST with long Base64-like data parameter to named web host</strong> · Medium</summary>

- **Description:** PowerShell POST with long Base64-like data parameter to named web host. Query characters cannot prove encoding purpose, payload content or C2.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R672_PowerShellBase64LikeHttpPostParameterRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R673 — Script HTTP GET with repeated double-percent-encoded segments</strong> · Low</summary>

- **Description:** Script HTTP GET with repeated double-percent-encoded segments. This is URL-encoding shape, not a proved custom encoder, malware or successful execution.
- **Category:** HttpApi
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R673_ScriptProcessRepeatedDoublePercentEncodedHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R682 — Rundll32/MSHTA browser-agent HTTP heartbeat-shaped GET sequence</strong> · Low</summary>

- **Description:** Rundll32/MSHTA browser-agent HTTP heartbeat-shaped GET sequence; No browser impersonation intent, HTTP response, C2 beacon or executable identity proof is established.
- **Category:** HttpApi
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R682_SystemUtilityBrowserAgentHttpGetHeartbeatRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R686 — Bitsadmin-associated cleartext HTTP GET to direct public IP</strong> · Medium</summary>

- **Description:** Bitsadmin-associated cleartext HTTP GET to direct public IP. The original Sigma command-line transfer flags and local output path are unavailable; an HTTP GET is not proof of file download or execution.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R686_BitsadminDirectIpCleartextHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R687 — Certutil-associated cleartext HTTP GET to direct public IP</strong> · Medium</summary>

- **Description:** Certutil-associated cleartext HTTP GET to direct public IP. Certutil URL-cache/verify flags and filesystem destination are not observable; no completed download is inferred.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R687_CertutilDirectIpCleartextHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R688 — Wget-associated cleartext HTTP GET to direct public IP</strong> · Medium</summary>

- **Description:** Wget-associated cleartext HTTP GET to direct public IP. The original suspicious local output-path condition is unavailable; observed request does not establish saved content.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R688_WgetDirectIpCleartextHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R689 — Curl-associated contact to selected file-sharing service host</strong> · Low</summary>

- **Description:** Curl-associated contact to selected file-sharing service host. The source rule requires command-line download/output flags and suspicious extension; SNI/HTTP host contact alone does not prove a file download.
- **Category:** HttpApi
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R689_CurlFileSharingServiceHostEgressRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R690 — Curl-associated cleartext HTTP GET for suspicious file extension</strong> · Medium</summary>

- **Description:** Curl-associated cleartext HTTP GET for suspicious file extension. Curl output-file arguments and local filesystem destination are unavailable; request path does not prove content was received or written.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R690_CurlSuspiciousExtensionCleartextHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R696 — Bitsadmin-associated contact to selected file-sharing service</strong> · Medium</summary>

- **Description:** Bitsadmin-associated contact to selected file-sharing service. Command-line transfer switches, output path and completed download are not observed.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R696_BitsadminFileSharingServiceContactRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R697 — Certutil-associated contact to selected file-sharing service</strong> · Medium</summary>

- **Description:** Certutil-associated contact to selected file-sharing service. Certutil URL-cache/verify flags and any downloaded file are not observable.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R697_CertutilFileSharingServiceContactRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R698 — PowerShell-associated contact to selected file-sharing service</strong> · Medium</summary>

- **Description:** PowerShell-associated contact to selected file-sharing service. PowerShell download APIs, script contents, local file writes and transfer success are not visible.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R698_PowerShellFileSharingServiceContactRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R699 — Office process cleartext HTTP GET for executable or script-like path</strong> · Medium</summary>

- **Description:** Office process cleartext HTTP GET for executable or script-like path. Office command-line URL invocation and saved-file destination are unavailable; a GET path is not proof of download.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R699_OfficeProcessSuspiciousExtensionHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R722 — Bitsadmin suspicious-extension cleartext HTTP GET</strong> · Medium</summary>

- **Description:** A bitsadmin.exe process is associated with an outbound cleartext HTTP GET whose URI ends in a script, executable, archive, webshell, or similar high-risk extension. Command-line BITS flags, local target path, response, file write, and completed download are not observed.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R722_BitsadminSuspiciousExtensionHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R725 — Curl or Wget cleartext GET with browser-like User-Agent</strong> · Low</summary>

- **Description:** Curl or Wget is associated with an outbound cleartext HTTP GET carrying a browser-like Mozilla User-Agent. Interactive-shell or scheduled-job context and spoofing intent are not visible, so this is only an observable process/header mismatch.
- **Category:** HttpApi
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R725_CurlWgetBrowserUserAgentHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R760 — macOS-style script process with browser-like User-Agent</strong> · Low</summary>

- **Description:** osascript, Python, or Python3 is associated with an outbound cleartext HTTP GET/POST carrying a browser-like Macintosh User-Agent. LaunchAgent origin, interactive context, spoofing intent, response and security outcome are not observed.
- **Category:** HttpApi
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R760_MacScriptBrowserUserAgentHttpRequestRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R828 — wget cleartext tar GET using public direct-IP HTTP host</strong> · Medium</summary>

- **Description:** Wget process and direct-IP HTTP tar request are visible; original HTTPS certificate bypass flag, file write and archive contents are not.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R828_WgetDirectIpTarHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R829 — cleartext executable GET from a .zip top-level domain</strong> · Medium</summary>

- **Description:** Observed HTTP executable-extension request to a .zip domain only; file write, MOTW stream content and transfer completion are not seen.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R829_ZipTldExecutableHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R830 — two distinct executable GET paths at one public IP host</strong> · Medium</summary>

- **Description:** Distinct cleartext executable requests to one public direct-IP HTTP origin are observed; no Zone.Identifier stream, downloaded file or execution is proven.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R830_DirectIpDistinctExecutableGetRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R896 — Regsvr32-attributed public HTTP scriptlet GET</strong> · Medium</summary>

- **Description:** Local regsvr32 attribution and a public HTTP GET ending in .sct; scriptlet execution, module load, command line and authorization are unknown.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R896_Regsvr32PublicScriptletHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [896-900](batches/RULE_BATCH_896-900.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R897 — CMSTP-attributed public HTTP INF GET</strong> · Medium</summary>

- **Description:** Local cmstp attribution and a public HTTP GET ending in .inf; profile installation, command line, DLL load and privilege change are unknown.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R897_CmstpPublicInfHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [896-900](batches/RULE_BATCH_896-900.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R907 — MSHTA public HTTP GET for image or PDF suffix</strong> · Medium</summary>

- **Description:** MSHTA public HTTP GET for .png, .jpg or .pdf. File contents, polyglot format and execution are unknown.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R907_MshtaPublicDisguisedArtifactGetRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R926 — Odbcconf public HTTP DLL GET</strong> · Medium</summary>

- **Description:** Odbcconf-attributed public HTTP GET for a DLL path. REGSVR arguments, DLL load, execution and authorization are not observed.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R926_OdbcconfPublicDllHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R927 — Cscript public HTTP scriptlet GET</strong> · Medium</summary>

- **Description:** Cscript-attributed public HTTP GET for a .sct resource. PubPrn invocation, script moniker and script execution are not observed.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R927_CscriptPublicScriptletHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R928 — JamPlus public HTTP Jam-file GET</strong> · Medium</summary>

- **Description:** JamPlus-attributed cleartext HTTP GET for a .jam resource. Build invocation, file contents, child process and execution are unknown.
- **Category:** HttpApi
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R928_JamplusPublicJamHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### ICMP: 2 rules

<details>
<summary>Choose a rule from 2 ICMP entries</summary>

<details>
<summary><strong>R021 — ICMP Tunneling Suspicion</strong> · Low</summary>

- **Description:** Possible ICMP tunneling
- **Category:** ICMP
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R021_IcmpTunnelingSuspicionRule.cs)
- **Detailed evidence and test scenarios:** [021-025](batches/RULE_BATCH_021-025.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R033 — ICMP Oversized Echo Payload</strong> · Low</summary>

- **Description:** Oversized ICMP echo payload
- **Category:** ICMP
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R033_IcmpOversizedEchoPayloadRule.cs)
- **Detailed evidence and test scenarios:** [031-035](batches/RULE_BATCH_031-035.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Identity: 1 rules

<details>
<summary>Choose a rule from 1 Identity entries</summary>

<details>
<summary><strong>R004 — Brute Force</strong> · High</summary>

- **Description:** Repeated authentication attempts
- **Category:** Identity
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R004_BruteForceRule.cs)
- **Detailed evidence and test scenarios:** [001-005](batches/RULE_BATCH_001-005.md)
- **Verification record:** See historical verification record

</details>

</details>

### IdentityAccess: 28 rules

<details>
<summary>Choose a rule from 28 IdentityAccess entries</summary>

<details>
<summary><strong>R123 — Suspicious VPN Login Path</strong> · High</summary>

- **Description:** Detects internal clients reaching external VPN portal login paths with explicit VPN appliance and SSO/login context, rather than any generic login page.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R123_SuspiciousVpnLoginPathRule.cs)
- **Detailed evidence and test scenarios:** [121-125](batches/RULE_BATCH_121-125.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R124 — External RDP Exposure Attempt</strong> · High</summary>

- **Description:** Detects RDP traffic that crosses an internal-external boundary with real RDP protocol evidence, rather than any mention of remote desktop.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R124_ExternalRdpExposureAttemptRule.cs)
- **Detailed evidence and test scenarios:** [121-125](batches/RULE_BATCH_121-125.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R125 — External WinRM Exposure Attempt</strong> · High</summary>

- **Description:** Detects WinRM or WSMAN traffic that crosses an internal-external boundary with real management protocol evidence.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R125_ExternalWinrmExposureAttemptRule.cs)
- **Detailed evidence and test scenarios:** [121-125](batches/RULE_BATCH_121-125.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R126 — External SSH Brute Candidate</strong> · High</summary>

- **Description:** Detects repeated SSH authentication failures across a boundary with thresholded evidence, rather than any SSH mention.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R126_ExternalSshBruteCandidateRule.cs)
- **Detailed evidence and test scenarios:** [126-130](batches/RULE_BATCH_126-130.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R127 — Admin Portal Access From Internet</strong> · High</summary>

- **Description:** Detects cross-boundary access to explicit admin portal paths, while suppressing ordinary public login pages and appliance-specific portals handled elsewhere.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R127_AdminPortalAccessFromInternetRule.cs)
- **Detailed evidence and test scenarios:** [126-130](batches/RULE_BATCH_126-130.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R128 — Network Appliance Management Exposure</strong> · High</summary>

- **Description:** Detects cross-boundary access to explicit network-appliance management portals with vendor or appliance context.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R128_NetworkApplianceManagementExposureRule.cs)
- **Detailed evidence and test scenarios:** [126-130](batches/RULE_BATCH_126-130.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R129 — Suspicious SAML OIDC Callback Traffic</strong> · Medium</summary>

- **Description:** Detects SAML or OIDC callback traffic only when the callback carries suspicious token leakage or insecure redirect patterns.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R129_SuspiciousSamlOidcCallbackTrafficRule.cs)
- **Detailed evidence and test scenarios:** [126-130](batches/RULE_BATCH_126-130.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R130 — Credential Stuffing Against Web Login</strong> · High</summary>

- **Description:** Detects thresholded bursts of login submissions with failures or many identities against the same web login path.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R130_CredentialStuffingAgainstWebLoginRule.cs)
- **Detailed evidence and test scenarios:** [126-130](batches/RULE_BATCH_126-130.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R131 — HTTP Authentication Failure Spike</strong> · Medium</summary>

- **Description:** Detects thresholded spikes of HTTP authentication failures with real auth context, instead of generic 403 noise.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R131_HttpAuthenticationFailureSpikeRule.cs)
- **Detailed evidence and test scenarios:** [131-135](batches/RULE_BATCH_131-135.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R132 — Rapid Country Change For Source Identity</strong> · Medium</summary>

- **Description:** Detects login-related events where the same extracted identity appears from multiple countries in a short window.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R132_RapidCountryChangeForSourceIdentityRule.cs)
- **Detailed evidence and test scenarios:** [131-135](batches/RULE_BATCH_131-135.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R133 — Basic Authentication Over Cleartext</strong> · High</summary>

- **Description:** Detects actual Basic Authorization headers sent over cleartext HTTP, rather than any mention of basic auth.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R133_BasicAuthenticationOverCleartextRule.cs)
- **Detailed evidence and test scenarios:** [131-135](batches/RULE_BATCH_131-135.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R134 — API Token In URL Query</strong> · High</summary>

- **Description:** Detects strong API-token-like query parameters with opaque values in request URIs, suppressing benign state and csrf parameters.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R134_ApiTokenInUrlQueryRule.cs)
- **Detailed evidence and test scenarios:** [131-135](batches/RULE_BATCH_131-135.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R135 — Bearer Token Over Cleartext HTTP</strong> · High</summary>

- **Description:** Detects actual Bearer Authorization headers sent over cleartext HTTP.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R135_BearerTokenOverCleartextHttpRule.cs)
- **Detailed evidence and test scenarios:** [131-135](batches/RULE_BATCH_131-135.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R136 — Session Cookie Over Cleartext HTTP</strong> · Medium</summary>

- **Description:** Detects recognizable session cookies sent over cleartext HTTP with opaque cookie values.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R136_SessionCookieOverCleartextHttpRule.cs)
- **Detailed evidence and test scenarios:** [136-140](batches/RULE_BATCH_136-140.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R137 — Password Reset Or Enrollment Spike</strong> · Medium</summary>

- **Description:** Detects repeated password-reset or MFA-enrollment actions in a short window, rather than any mention of recovery text.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R137_PasswordResetOrEnrollmentSpikeRule.cs)
- **Detailed evidence and test scenarios:** [136-140](batches/RULE_BATCH_136-140.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R549 — Cross-Subnet Default Basic Credential Fanout</strong> · High</summary>

- **Description:** A private IPv4 source sends parser-confirmed default Basic Authorization to admin routes in three distinct private /24 networks within five minutes; authentication outcomes are unknown.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R549_CrossSubnetDefaultBasicCredentialFanoutRule.cs)
- **Detailed evidence and test scenarios:** [549-549](batches/RULE_BATCH_549-549.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R553 — Cross-Subnet SMB2 Write Request Fanout</strong> · High</summary>

- **Description:** A private IPv4 client sends first-segment SMB2 WRITE request shapes to three distinct other private /24s in five minutes; outcomes and share identities are unknown.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R553_CrossSubnetSmb2WriteRequestFanoutRule.cs)
- **Detailed evidence and test scenarios:** [553-553](batches/RULE_BATCH_553-553.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R556 — External SMB2 Write Request Private-Subnet Fanout</strong> · High</summary>

- **Description:** A public IPv4 client sends bounded SMB2 WRITE request shapes to three distinct RFC1918 destination /24s in five minutes; authentication and write outcomes are unknown.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R556_ExternalSmb2WriteTargetSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [556-556](batches/RULE_BATCH_556-556.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R582 — Outbound Default HTTP Basic Admin Credential Fanout</strong> · High</summary>

- **Description:** One private source sends parser-confirmed known-default Basic credentials to admin routes at three public destination /24 networks in five minutes.
- **Category:** IdentityAccess
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R582_OutboundDefaultBasicAdminSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [580-584](batches/RULE_BATCH_580-584.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R644 — Internal RDP listener SYN-ACK response to public client</strong> · Medium</summary>

- **Description:** Internal RDP listener SYN-ACK response to public client. Observed evidence only; An SYN-ACK proves network handshake response only, not authenticated RDP access or true external Internet exposure through NAT.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R644_RdpPublicClientSynAckExposureEvidenceRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R648 — VNC private listener SYN-ACK response to a public client</strong> · Medium</summary>

- **Description:** VNC private listener SYN-ACK response to a public client. R124 RDP exposure and R644 RDP SYN-ACK have a different service; this is VNC TCP/5900 response only.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R648_VncListenerPublicSynAckResponseRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R649 — WinRM private listener SYN-ACK response to a public client</strong> · Medium</summary>

- **Description:** WinRM private listener SYN-ACK response to a public client. R125 flags inbound WinRM service access, not observed server SYN-ACK; this requires response direction and flags.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R649_WinRmListenerPublicSynAckResponseRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R691 — Private SMB listener SYN-ACK response to a public client</strong> · Medium</summary>

- **Description:** Private SMB listener SYN-ACK response to a public client. The original Event 4624 successful logon is not available. SYN-ACK proves only a TCP listener response, not SMB authentication or successful login.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R691_SmbListenerPublicClientSynAckEvidenceRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R692 — Outlook-associated external WebDAV request or SMB SYN attempt</strong> · Medium</summary>

- **Description:** Outlook-associated external WebDAV request or SMB SYN attempt. The original registry-access evidence is unavailable. Network activity does not prove CVE-2023-23397 exploitation, NTLM disclosure, or credential capture.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R692_OutlookExternalWebDavOrSmbAttemptRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R693 — SnippingTool-associated external SMB SYN or cleartext HTTP GET</strong> · Medium</summary>

- **Description:** SnippingTool-associated external SMB SYN or cleartext HTTP GET. The ms-screensketch URI handler and filePath command-line value are not observed. Do not claim CVE exploitation, SSRF or NTLM leakage.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R693_SnippingToolExternalRemoteResourceAttemptRule.cs)
- **Detailed evidence and test scenarios:** [686-695](batches/RULE_BATCH_686-695.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R759 — Linux VNC process public-client SYN-ACK exposure evidence</strong> · Medium</summary>

- **Description:** x11vnc, vncserver, Xvnc, or Xtigervnc is associated with a private-host TCP/5900 SYN-ACK to a public client. Authentication, listener ownership beyond best-effort process attribution, session establishment and authorization are not observed.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R759_LinuxVncProcessPublicSynAckRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R832 — CertOC process GET to a direct public IP HTTP origin</strong> · Medium</summary>

- **Description:** CertOC-associated direct-IP cleartext HTTP GET only; command-line GetCACAPS, CA response, material write and certificate trust are not visible.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R832_CertocPublicIpHttpGetRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R915 — Dsconfigad private LDAP then Kerberos SYN</strong> · Medium</summary>

- **Description:** Same dsconfigad PID and private peer TCP/389 SYN then TCP/88 SYN. Domain enrollment, account creation and authentication are unknown.
- **Category:** IdentityAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R915_DsconfigadLdapThenKerberosSynRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### IdentityAdvanced: 20 rules

<details>
<summary>Choose a rule from 20 IdentityAdvanced entries</summary>

<details>
<summary><strong>R273 — Impossible Travel Authentication Sequence</strong> · High</summary>

- **Description:** Detects Impossible Travel Authentication Sequence only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R273_ImpossibleTravelAuthenticationSequenceRule.cs)
- **Detailed evidence and test scenarios:** [271-275](batches/RULE_BATCH_271-275.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R274 — MFA Push Fatigue Pattern</strong> · High</summary>

- **Description:** Detects MFA Push Fatigue Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R274_MFAPushFatiguePatternRule.cs)
- **Detailed evidence and test scenarios:** [271-275](batches/RULE_BATCH_271-275.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R275 — OAuth Device Code Phishing Indicator</strong> · High</summary>

- **Description:** Detects OAuth Device Code Phishing Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R275_OAuthDeviceCodePhishingIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [271-275](batches/RULE_BATCH_271-275.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R276 — OAuth Consent Grant Abuse Indicator</strong> · High</summary>

- **Description:** Detects OAuth Consent Grant Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R276_OAuthConsentGrantAbuseIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [276-280](batches/RULE_BATCH_276-280.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R277 — Legacy Protocol Authentication Attempt</strong> · Medium</summary>

- **Description:** Detects Legacy Protocol Authentication Attempt only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R277_LegacyProtocolAuthenticationAttemptRule.cs)
- **Detailed evidence and test scenarios:** [276-280](batches/RULE_BATCH_276-280.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R278 — Password Spray Low And Slow Across Accounts</strong> · High</summary>

- **Description:** Detects Password Spray Low And Slow Across Accounts only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R278_PasswordSprayLowAndSlowAcrossAccountsRule.cs)
- **Detailed evidence and test scenarios:** [276-280](batches/RULE_BATCH_276-280.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R279 — Credential Stuffing Rotating User Agent</strong> · High</summary>

- **Description:** Detects Credential Stuffing Rotating User Agent only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R279_CredentialStuffingRotatingUserAgentRule.cs)
- **Detailed evidence and test scenarios:** [276-280](batches/RULE_BATCH_276-280.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R280 — Session Token Replay Across Geographies</strong> · High</summary>

- **Description:** Detects Session Token Replay Across Geographies only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R280_SessionTokenReplayAcrossGeographiesRule.cs)
- **Detailed evidence and test scenarios:** [276-280](batches/RULE_BATCH_276-280.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R281 — Suspicious Admin Console Login To Cloud</strong> · High</summary>

- **Description:** Detects Suspicious Admin Console Login To Cloud only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R281_SuspiciousAdminConsoleLoginToCloudRule.cs)
- **Detailed evidence and test scenarios:** [281-285](batches/RULE_BATCH_281-285.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R282 — VPN Login Followed By Internal Scan</strong> · Critical</summary>

- **Description:** Detects VPN Login Followed By Internal Scan only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R282_VPNLoginFollowedByInternalScanRule.cs)
- **Detailed evidence and test scenarios:** [281-285](batches/RULE_BATCH_281-285.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R283 — SAML RelayState Injection Pattern</strong> · High</summary>

- **Description:** Detects SAML RelayState Injection Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R283_SAMLRelayStateInjectionPatternRule.cs)
- **Detailed evidence and test scenarios:** [281-285](batches/RULE_BATCH_281-285.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R284 — OIDC Authorization Code Leakage In URL</strong> · High</summary>

- **Description:** Detects OIDC Authorization Code Leakage In URL only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R284_OIDCAuthorizationCodeLeakageInURLRule.cs)
- **Detailed evidence and test scenarios:** [281-285](batches/RULE_BATCH_281-285.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R285 — SCIM Bulk User Enumeration</strong> · Medium</summary>

- **Description:** Detects SCIM Bulk User Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R285_SCIMBulkUserEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [281-285](batches/RULE_BATCH_281-285.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R286 — LDAP Simple Bind Over Cleartext External</strong> · High</summary>

- **Description:** Shadow-only candidate for a verified plaintext LDAPv3 nonanonymous simple BindRequest crossing an internal/external boundary; no authentication outcome inferred.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R286_LDAPSimpleBindOverCleartextExternalRule.cs)
- **Detailed evidence and test scenarios:** [286-290](batches/RULE_BATCH_286-290.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R287 — Kerberos Preauth Failure Distributed Spray</strong> · High</summary>

- **Description:** Detects Kerberos Preauth Failure Distributed Spray only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R287_KerberosPreauthFailureDistributedSprayRule.cs)
- **Detailed evidence and test scenarios:** [286-290](batches/RULE_BATCH_286-290.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R288 — NTLMv1 Authentication Observed</strong> · High</summary>

- **Description:** Detects NTLMv1 Authentication Observed only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R288_NTLMv1AuthenticationObservedRule.cs)
- **Detailed evidence and test scenarios:** [286-290](batches/RULE_BATCH_286-290.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R289 — RADIUS Authentication Failure Burst</strong> · Medium</summary>

- **Description:** Detects RADIUS Authentication Failure Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R289_RADIUSAuthenticationFailureBurstRule.cs)
- **Detailed evidence and test scenarios:** [286-290](batches/RULE_BATCH_286-290.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R290 — Citrix Gateway Exploit Probe</strong> · High</summary>

- **Description:** Detects Citrix Gateway Exploit Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R290_CitrixGatewayExploitProbeRule.cs)
- **Detailed evidence and test scenarios:** [286-290](batches/RULE_BATCH_286-290.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R291 — Fortinet SSL VPN Exploit Probe</strong> · High</summary>

- **Description:** Detects Fortinet SSL VPN Exploit Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R291_FortinetSSLVPNExploitProbeRule.cs)
- **Detailed evidence and test scenarios:** [291-295](batches/RULE_BATCH_291-295.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R292 — Palo Alto GlobalProtect Exploit Probe</strong> · High</summary>

- **Description:** Detects Palo Alto GlobalProtect Exploit Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** IdentityAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R292_PaloAltoGlobalProtectExploitProbeRule.cs)
- **Detailed evidence and test scenarios:** [291-295](batches/RULE_BATCH_291-295.md)
- **Verification record:** 0 executed (reported)

</details>

</details>

### Impact: 1 rules

<details>
<summary>Choose a rule from 1 Impact entries</summary>

<details>
<summary><strong>R840 — Same public client repeated HTTP GET to private service path</strong> · Medium</summary>

- **Description:** Eight coherent same-path public-to-private cleartext HTTP/80 GET packets over twenty seconds; no network-layer denial-of-service impact or resource depletion inferred.
- **Category:** Impact
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R840_PublicRepeatedSamePathGetRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Industrial: 1 rules

<details>
<summary>Choose a rule from 1 Industrial entries</summary>

<details>
<summary><strong>R853 — One internal telemetry peer sends TCP/1883 with two source MACs</strong> · Medium</summary>

- **Description:** Two coherent same-endpoint internal TCP/1883 reporting payload packets carry distinct canonical Ethernet source MACs within 60s; no enrolled identity, message spoof or physical process divergence established.
- **Category:** Industrial
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R853_ReportingPeerSourceMacChangeRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### InitialAccess: 7 rules

<details>
<summary>Choose a rule from 7 InitialAccess entries</summary>

<details>
<summary><strong>R839 — Public encoded traversal GET then web-worker public TLS</strong> · Medium</summary>

- **Description:** Inbound cleartext encoded traversal GET on HTTP/80 followed by w3wp process attributed outbound TLS/8443 from the private web host; exploit success and worker causality unknown.
- **Category:** InitialAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R839_TraversalGetThenWebWorkerTlsRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R875 — Public DNP3-port TCP SYN followed by application-sized data</strong> · Medium</summary>

- **Description:** One public client sends TCP SYN then application-sized TCP data to the same private TCP/20000 host within 40s; no DNP3 decoder, authenticated session or device command is implied.
- **Category:** InitialAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R875_PublicDnp3SynThenPayloadRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R878 — Public SSH SYN followed by same-flow payload</strong> · Medium</summary>

- **Description:** Public TCP/22 SYN to a private host is followed by application-sized data from the same public client and source port within 40s; Linux identity, SSH authentication, authorization and OT asset role are unknown.
- **Category:** InitialAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R878_PublicSshSynThenPayloadRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R885 — Public CGI POST then same host bash-attributed public TLS</strong> · Medium</summary>

- **Description:** Public POST to a private CGI diagnostic path precedes bash-attributed public TLS/8443 to a different IP from that host within 60s; no process spawn, command execution, exploitation or causality proven.
- **Category:** InitialAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R885_PublicCgiPostThenBashTlsRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R891 — Public VNC SYN followed by same-flow client data</strong> · Medium</summary>

- **Description:** Public SYN/5900 to private host followed by client application-sized data on the same source port within 40s; VNC authentication, session takeover, GUI action and file transfer are not observed.
- **Category:** InitialAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R891_PublicVncSynThenPayloadRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R902 — Public SSH attempt then screensharingd VNC SYN-ACK</strong> · Medium</summary>

- **Description:** Public TCP/22 SYN to a private host followed by locally attributed screensharingd TCP/5900 SYN-ACK back to the same public peer within 45s; no SSH or VNC authentication or linked user session is established.
- **Category:** InitialAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R902_PublicSshThenScreensharingVncResponseRule.cs)
- **Detailed evidence and test scenarios:** [901-905](batches/RULE_BATCH_901-905.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R922 — Public HTTP POST to PowerShell Web Access path</strong> · Medium</summary>

- **Description:** Public cleartext HTTP POST to /pswa/default.aspx or /pswa/ on a private host. PSWA installation, credentials and execution are unknown.
- **Category:** InitialAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R922_PublicPswaLoginRequestRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### IotOt: 17 rules

<details>
<summary>Choose a rule from 17 IotOt entries</summary>

<details>
<summary><strong>R113 — MQTT Broker Connection to Unapproved Host</strong> · High</summary>

- **Description:** Detects MQTT connections to external or public broker infrastructure, while suppressing ordinary internal-broker traffic and keyword-only records.
- **Category:** IotOt
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R113_MQTTBrokerConnectionToUnapprovedHostRule.cs)
- **Detailed evidence and test scenarios:** [111-115](batches/RULE_BATCH_111-115.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R114 — MQTT Topic Enumeration</strong> · Medium</summary>

- **Description:** Detects MQTT wildcard subscriptions or unusually broad topic-subscription sweeps from a single source, rather than treating generic mqtt text as enumeration.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R114_MQTTTopicEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [111-115](batches/RULE_BATCH_111-115.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R115 — MQTT High-Frequency Publish Burst</strong> · Medium</summary>

- **Description:** Detects unusually high-frequency MQTT publish bursts, with stronger gating for internal brokers so ordinary sensor chatter does not alert by default.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R115_MQTTHighFrequencyPublishBurstRule.cs)
- **Detailed evidence and test scenarios:** [111-115](batches/RULE_BATCH_111-115.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R116 — UPnP Exposure / Discovery Abuse</strong> · Medium</summary>

- **Description:** Detects UPnP/SSDP discovery abuse when discovery traffic leaves the local network or becomes a strong internal discovery burst, rather than on one-off local discovery chatter.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R116_UPnPExposureDiscoveryAbuseRule.cs)
- **Detailed evidence and test scenarios:** [116-120](batches/RULE_BATCH_116-120.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R117 — Telnet Login Attempt to IoT Device</strong> · High</summary>

- **Description:** Detects telnet login attempts that include real authentication context against likely IoT or network-device targets, rather than generic port 23 traffic alone.
- **Category:** IotOt
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R117_TelnetLoginAttemptToIoTDeviceRule.cs)
- **Detailed evidence and test scenarios:** [116-120](batches/RULE_BATCH_116-120.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R118 — Default-Credential IoT Attempt</strong> · Critical</summary>

- **Description:** Detects default-credential attempts only when the record contains both real authentication context and likely IoT or device-target indicators.
- **Category:** IotOt
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R118_DefaultCredentialIoTAttemptRule.cs)
- **Detailed evidence and test scenarios:** [116-120](batches/RULE_BATCH_116-120.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R119 — Camera / NVR External Beacon</strong> · High</summary>

- **Description:** Detects repeated external beaconing or direct RTSP-style external streaming from camera or NVR-like devices, while suppressing isolated one-off traffic.
- **Category:** IotOt
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R119_CameraNVRExternalBeaconRule.cs)
- **Detailed evidence and test scenarios:** [116-120](batches/RULE_BATCH_116-120.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R120 — Modbus Traffic Outside Approved Segment</strong> · Critical</summary>

- **Description:** Detects Modbus traffic that crosses a strong trust boundary or carries write-like function context outside a tight local segment, rather than any mention of modbus.
- **Category:** IotOt
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R120_ModbusTrafficOutsideApprovedSegmentRule.cs)
- **Detailed evidence and test scenarios:** [116-120](batches/RULE_BATCH_116-120.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R121 — BACnet Discovery from Non-Admin Host</strong> · High</summary>

- **Description:** Detects BACnet discovery activity only when it carries real who-is or discovery semantics from non-admin-like sources or crosses unexpected boundaries.
- **Category:** IotOt
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R121_BACnetDiscoveryFromNonAdminHostRule.cs)
- **Detailed evidence and test scenarios:** [121-125](batches/RULE_BATCH_121-125.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R122 — CoAP / Zigbee Gateway Suspicious Egress</strong> · High</summary>

- **Description:** Detects suspicious external egress from CoAP or Zigbee gateway-like traffic, while suppressing isolated weak matches that lack gateway context or repetition.
- **Category:** IotOt
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IotOt/R122_CoAPZigbeeGatewaySuspiciousEgressRule.cs)
- **Detailed evidence and test scenarios:** [121-125](batches/RULE_BATCH_121-125.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R800 — scada-named process field-device SYN then public HTTP API GET</strong> · Medium</summary>

- **Description:** scada-named process field-device SYN then public HTTP API GET. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R800_ScadaDeviceSynThenPublicHttpRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R801 — EtherNet/IP ListIdentity probe then Modbus SYN to same private device</strong> · Medium</summary>

- **Description:** EtherNet/IP ListIdentity probe then Modbus SYN to same private device. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R801_CipIdentityThenModbusSynRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R802 — python-attributed probes of three OT protocol ports on one device</strong> · Medium</summary>

- **Description:** python-attributed probes of three OT protocol ports on one device. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R802_PythonOtServiceMultiPortProbeRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R803 — CoAP multicast discovery then process-linked direct public DNS TXT</strong> · Medium</summary>

- **Description:** CoAP multicast discovery then process-linked direct public DNS TXT. Packet/process shape only; no authorization, exploitation, transfer completion, command execution or compromise inferred.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R803_CoapDiscoveryThenPublicDnsTxtRule.cs)
- **Detailed evidence and test scenarios:** [796-805](batches/RULE_BATCH_796-805.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R932 — Public MQTT control-topic publish request</strong> · Medium</summary>

- **Description:** Public source sends parsed MQTT control-topic PUBLISH to private TCP/1883. Broker policy, acknowledgement, authorization and device action are unknown.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R932_PublicMqttControlPublishRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R933 — MQTT private client SYN then retained PUBLISH</strong> · Medium</summary>

- **Description:** Private client TCP/1883 SYN to private broker followed by same-flow parsed retained control-topic PUBLISH. Reconnection, delivery, command application and device response are unknown.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R933_MqttSynThenRetainedPublishRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R934 — MQTT client TLS to distinct public broker peers</strong> · Medium</summary>

- **Description:** Same private mosquitto_pub PID sends TLS/8883 to two distinct public peers within 45s. Broker trust-root changes, broker identity, MQTT session and policy are unknown.
- **Category:** IotOt
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R934_MqttBrokerTlsDifferentPublicPeersRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### IotOtAdvanced: 57 rules

<details>
<summary>Choose a rule from 57 IotOtAdvanced entries</summary>

<details>
<summary><strong>R223 — ICS Protocol To Internet</strong> · Critical</summary>

- **Description:** Detects concrete ICS or OT protocol traffic from internal sources to external destinations, rather than any loose industrial keyword hit.
- **Category:** IotOtAdvanced
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R223_IcsProtocolToInternetRule.cs)
- **Detailed evidence and test scenarios:** [221-225](batches/RULE_BATCH_221-225.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R224 — DNP3 Traffic Outside Approved Segment</strong> · High</summary>

- **Description:** Detects DNP3 traffic that crosses an unexpected boundary or segment, rather than any bare port-20000 or keyword hit.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R224_Dnp3TrafficOutsideApprovedSegmentRule.cs)
- **Detailed evidence and test scenarios:** [221-225](batches/RULE_BATCH_221-225.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R225 — S7comm Traffic Outside Approved Segment</strong> · High</summary>

- **Description:** Detects Siemens S7 communication crossing unexpected boundaries or segments, rather than loose port-102 matches.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R225_S7CommTrafficOutsideApprovedSegmentRule.cs)
- **Detailed evidence and test scenarios:** [221-225](batches/RULE_BATCH_221-225.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R226 — EtherNetIP CIP Discovery Burst</strong> · Medium</summary>

- **Description:** Detects bursts of EtherNet/IP CIP discovery such as ListIdentity across multiple destinations, instead of any stray CIP keyword.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R226_EthernetipCipDiscoveryBurstRule.cs)
- **Detailed evidence and test scenarios:** [226-230](batches/RULE_BATCH_226-230.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R227 — Profinet DCP Discovery Suspicious</strong> · Medium</summary>

- **Description:** Detects suspicious bursts of Profinet DCP identify requests, rather than any generic Profinet or DCP mention.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R227_ProfinetDcpDiscoverySuspiciousRule.cs)
- **Detailed evidence and test scenarios:** [226-230](batches/RULE_BATCH_226-230.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R228 — OPC UA Internet Egress</strong> · High</summary>

- **Description:** Detects concrete OPC UA traffic from internal sources to external destinations, rather than any loose opc.tcp or port-4840 match.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R228_OpcUaInternetEgressRule.cs)
- **Detailed evidence and test scenarios:** [226-230](batches/RULE_BATCH_226-230.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R229 — MQTT Retained Topic Abuse</strong> · Medium</summary>

- **Description:** Detects retained MQTT publishes only when they target suspicious control topics or public or external brokers, instead of flagging every retained message.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R229_MqttRetainedTopicAbuseRule.cs)
- **Detailed evidence and test scenarios:** [226-230](batches/RULE_BATCH_226-230.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R230 — MQTT Last Will Suspicious</strong> · Medium</summary>

- **Description:** Detects suspicious MQTT last-will usage only when it targets risky topics or public or external brokers, instead of any ordinary LWT configuration.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R230_MqttLastWillSuspiciousRule.cs)
- **Detailed evidence and test scenarios:** [226-230](batches/RULE_BATCH_226-230.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R231 — CoAP Multicast Discovery Burst</strong> · Medium</summary>

- **Description:** Detects bursts of CoAP multicast or /.well-known/core discovery, while suppressing isolated or non-discovery CoAP traffic.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R231_CoapMulticastDiscoveryBurstRule.cs)
- **Detailed evidence and test scenarios:** [231-235](batches/RULE_BATCH_231-235.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R232 — mDNS Service Enumeration Burst</strong> · Medium</summary>

- **Description:** Detects high-rate mDNS service enumeration only when the traffic carries real service-discovery semantics, not any stray bonjour or .local text.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R232_MdnsServiceEnumerationBurstRule.cs)
- **Detailed evidence and test scenarios:** [231-235](batches/RULE_BATCH_231-235.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R233 — Printer Admin Protocol External Access</strong> · Medium</summary>

- **Description:** Detects printer administration protocols exposed across an external or unexpected boundary only when printer-admin protocol semantics are present.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R233_PrinterAdminProtocolExternalAccessRule.cs)
- **Detailed evidence and test scenarios:** [231-235](batches/RULE_BATCH_231-235.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R234 — IP Camera RTSP External Stream</strong> · High</summary>

- **Description:** Detects RTSP camera streaming to or from an external destination with camera/RTSP evidence, rather than generic port 554 traffic.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R234_IpCameraRtspExternalStreamRule.cs)
- **Detailed evidence and test scenarios:** [231-235](batches/RULE_BATCH_231-235.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R235 — ONVIF Discovery From Workstation</strong> · Medium</summary>

- **Description:** Detects workstation-originated ONVIF/WS-Discovery probing when discovery semantics and burst behavior are present.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R235_OnvifDiscoveryFromWorkstationRule.cs)
- **Detailed evidence and test scenarios:** [231-235](batches/RULE_BATCH_231-235.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R236 — IoT Firmware Update Over Cleartext</strong> · High</summary>

- **Description:** Detects observable IoT firmware artifact requests over cleartext HTTP only when update artifact and IoT/device context are both present.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R236_IotFirmwareUpdateOverCleartextRule.cs)
- **Detailed evidence and test scenarios:** [236-240](batches/RULE_BATCH_236-240.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R237 — IoT Default Web Admin Access</strong> · High</summary>

- **Description:** Detects IoT/router/camera default admin web access attempts when default admin paths or credential tokens are present.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R237_IotDefaultWebAdminAccessRule.cs)
- **Detailed evidence and test scenarios:** [236-240](batches/RULE_BATCH_236-240.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R238 — Smart Home Hub Cloud Burst</strong> · Medium</summary>

- **Description:** Detects bursty cloud synchronization from smart-home hub context to vendor/cloud endpoints while suppressing isolated telemetry calls.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R238_SmartHomeHubCloudBurstRule.cs)
- **Detailed evidence and test scenarios:** [236-240](batches/RULE_BATCH_236-240.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R239 — Zigbee2MQTT Bridge Internet Access</strong> · High</summary>

- **Description:** Detects Zigbee2MQTT bridge context communicating with external destinations, especially MQTT control or bridge topics.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R239_Zigbee2MqttBridgeInternetAccessRule.cs)
- **Detailed evidence and test scenarios:** [236-240](batches/RULE_BATCH_236-240.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R240 — Modbus Write Function</strong> · Critical</summary>

- **Description:** Detects concrete Modbus write-function semantics and prioritizes writes crossing external or unexpected segment boundaries.
- **Category:** IotOtAdvanced
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R240_ModbusWriteFunctionRule.cs)
- **Detailed evidence and test scenarios:** [236-240](batches/RULE_BATCH_236-240.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R241 — BACnet Who-Is I-Am Burst</strong> · Medium</summary>

- **Description:** Detects BACnet Who-Is/I-Am discovery bursts using BACnet semantics and distinct-target/window evidence.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R241_BacnetWhoIsIAmBurstRule.cs)
- **Detailed evidence and test scenarios:** [241-245](batches/RULE_BATCH_241-245.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R242 — NTP Amplification Candidate</strong> · Medium</summary>

- **Description:** Detects NTP amplification candidate traffic only when UDP/NTP and amplification-prone command semantics such as monlist/mode7/readvar are present.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R242_NtpAmplificationCandidateRule.cs)
- **Detailed evidence and test scenarios:** [241-245](batches/RULE_BATCH_241-245.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R545 — External BACnet I-Am Announcement</strong> · High</summary>

- **Description:** Repeated parsed BACnet/IP I-Am advertisements from a public IPv4 source to an RFC1918 destination; does not assert spoofing or exploitation.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R545_ExternalBacnetIAmAnnouncementRule.cs)
- **Detailed evidence and test scenarios:** [545-545](batches/RULE_BATCH_545-545.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R546 — Outbound NTP Mode-7 Monlist Target Fanout</strong> · Medium</summary>

- **Description:** Wire-classified mode-7 monlist requests are addressed to three distinct public IPv4 destinations on UDP/123 from one RFC1918 source within five minutes; no response or exploit outcome is inferred.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R546_NtpMonlistOutboundTargetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [546-546](batches/RULE_BATCH_546-546.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R547 — External BACnet Who-Is Target Fanout</strong> · High</summary>

- **Description:** A public IPv4 source sends parsed BACnet Who-Is requests to three distinct RFC1918 destinations on UDP/47808 within five minutes; no response or device-control outcome is inferred.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R547_ExternalBacnetWhoIsTargetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [547-547](batches/RULE_BATCH_547-547.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R548 — External Modbus Write Target Fanout</strong> · Critical</summary>

- **Description:** One public IPv4 source addresses parsed Modbus/TCP write requests to three distinct RFC1918 targets within five minutes; no server outcome is inferred.
- **Category:** IotOtAdvanced
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R548_ExternalModbusWriteTargetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [548-548](batches/RULE_BATCH_548-548.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R550 — BACnet Cross-Boundary Discovery Reply Correlation</strong> · High</summary>

- **Description:** Two private BACnet endpoints emit I-Am-shaped UDP datagrams after a public source sent Who-Is-shaped datagrams to each within 60 seconds; authorization and device identities are unknown.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R550_BacnetCrossBoundaryDiscoveryReplyRule.cs)
- **Detailed evidence and test scenarios:** [550-550](batches/RULE_BATCH_550-550.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R551 — External BACnet Discovery Followed by Modbus Write Requests</strong> · High</summary>

- **Description:** One public IPv4 source sends bounded BACnet Who-Is requests followed within two minutes by Modbus write requests to each of two distinct private targets; outcomes and authorization are unknown.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R551_ExternalBacnetDiscoveryThenModbusWriteRule.cs)
- **Detailed evidence and test scenarios:** [551-551](batches/RULE_BATCH_551-551.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R552 — External NTP Mode-7 Monlist Private-Subnet Fanout</strong> · Medium</summary>

- **Description:** One public IPv4 source sends parser-classified NTP mode-7 monlist requests to three distinct RFC1918 destination /24s within five minutes; no server response or amplification is inferred.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R552_ExternalNtpMonlistPrivateSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [552-552](batches/RULE_BATCH_552-552.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R557 — Outbound Modbus Write Public-Subnet Fanout</strong> · High</summary>

- **Description:** One RFC1918 source issues bounded Modbus/TCP write requests to three distinct globally routable destination /24s within five minutes; no server outcome is inferred.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R557_OutboundModbusWritePublicSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [557-557](batches/RULE_BATCH_557-557.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R558 — Internal NTP Mode-7 Monlist Cross-Subnet Sweep</strong> · Medium</summary>

- **Description:** One RFC1918 source probes three distinct other RFC1918 /24 networks with parsed NTP mode-7 monlist requests in five minutes; no server outcome inferred.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R558_InternalNtpMonlistCrossSubnetSweepRule.cs)
- **Detailed evidence and test scenarios:** [558-558](batches/RULE_BATCH_558-558.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R559 — Internal Cross-Subnet BACnet Discovery Followed by Modbus Write Requests</strong> · High</summary>

- **Description:** One private IPv4 source sends BACnet Who-Is requests then Modbus write requests to targets in two distinct other private /24s; no control outcome is inferred.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R559_InternalCrossSubnetBacnetDiscoveryThenModbusWriteRule.cs)
- **Detailed evidence and test scenarios:** [559-559](batches/RULE_BATCH_559-559.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R560 — External BACnet Reply Followed by Modbus Write Request</strong> · High</summary>

- **Description:** One public peer sends BACnet Who-Is, observes a reverse I-Am-shaped datagram, then sends a Modbus write request to the same private target; outcomes unknown.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R560_ExternalBacnetReplyThenModbusWriteRule.cs)
- **Detailed evidence and test scenarios:** [560-560](batches/RULE_BATCH_560-560.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R563 — Default HTTP Admin Credential Then Modbus Write Request</strong> · High</summary>

- **Description:** A private client sends a known-default Basic admin request and later a Modbus write request to the same other-subnet private target; authentication and write outcomes are unknown.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R563_DefaultBasicThenModbusWriteRule.cs)
- **Detailed evidence and test scenarios:** [563-563](batches/RULE_BATCH_563-563.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R570 — Modbus Write Request Then Default HTTP Admin Credential</strong> · High</summary>

- **Description:** A private client sends a Modbus write request and later a known-default Basic HTTP admin request to the same other-subnet private target; authentication and write outcomes are unknown.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R570_ModbusWriteThenDefaultBasicAdminRule.cs)
- **Detailed evidence and test scenarios:** [570-570](batches/RULE_BATCH_570-570.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R583 — Outbound BACnet Who-Is Public Subnet Fanout</strong> · High</summary>

- **Description:** One private BACnet source sends classified Who-Is requests to three different public /24 networks in five minutes; device replies are unknown.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R583_OutboundBacnetWhoIsSubnetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [580-584](batches/RULE_BATCH_580-584.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R653 — Public-client Modbus non-write request multi-host sweep</strong> · Medium</summary>

- **Description:** Public-client Modbus non-write request multi-host sweep. R548 is Modbus WRITE cross-subnet fanout; R653 requires non-write request classification to three hosts in one private /24.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R653_PublicModbusNonWriteHostSweepRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R654 — Public-client S7Comm multi-host discovery sweep</strong> · High</summary>

- **Description:** Public-client S7Comm multi-host discovery sweep. R225 covers outside-segment S7, R478 block transfer; this requires one public client and three private S7 hosts in one /24.
- **Category:** IotOtAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R654_PublicS7CommHostSweepRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R655 — Public-client EtherNet/IP ListIdentity multi-host probe</strong> · Medium</summary>

- **Description:** Public-client EtherNet/IP ListIdentity multi-host probe. R488 generic CIP ListIdentity burst and R643 internal sequential scan; this is public-to-private fanout to three exact hosts.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R655_PublicEtherNetIpListIdentityHostSweepRule.cs)
- **Detailed evidence and test scenarios:** [646-655](batches/RULE_BATCH_646-655.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R679 — Private OT-service listener TCP SYN-ACK to public client</strong> · Medium</summary>

- **Description:** Private OT-service listener TCP SYN-ACK to public client; Port-associated SYN-ACK alone does not verify an ICS device, protocol decoder success, successful authentication or NAT exposure.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R679_IndustrialServicePortPublicClientSynAckRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R683 — Parsed cleartext HTTP POST on native Modbus TCP service port</strong> · Medium</summary>

- **Description:** Parsed cleartext HTTP POST on native Modbus TCP service port; A legitimate nonstandard HTTP service may use port 502; no ICS protocol masquerade intent or exploit is proved.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R683_HttpPostDetectedOnModbusServicePortRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R684 — Public OPC UA-port SYN and private-server SYN-ACK exchange</strong> · Medium</summary>

- **Description:** Public OPC UA-port SYN and private-server SYN-ACK exchange; The TCP exchange does not prove OPC UA payload, API execution, user approval, login or completed TCP handshake.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R684_OpcUaPublicClientSynSynAckExchangeRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R685 — Large parsed S7Comm response records from three private devices</strong> · Medium</summary>

- **Description:** Large parsed S7Comm response records from three private devices; Large response records do not establish directory listing, point/tag identification, device inventory or compromise.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R685_MultiDeviceLargeS7CommResponseFanInRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R702 — Known application protocol classified on an incompatible OT service port</strong> · Medium</summary>

- **Description:** Known application protocol classified on an incompatible OT service port. Protocol classification mismatch is not proof of an intercepting hook, asset compromise, malformed response or unauthorized tool.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R702_OtServiceProtocolClassificationMismatchRule.cs)
- **Detailed evidence and test scenarios:** [696-705](batches/RULE_BATCH_696-705.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R708 — Public client TFTP request followed by private-host transfer reply</strong> · Medium</summary>

- **Description:** Public client to private server: capture-attested TFTP RRQ or WRQ followed by its exact first DATA block 1 or ACK block 0 within 30 seconds. No transfer completion, file identity, firmware change, authorization or compromise established.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R708_PublicClientTftpExchangeToPrivateHostRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R709 — Public oversized cleartext HTTP request to management-style port</strong> · Medium</summary>

- **Description:** A public client sends a parser-coherent cleartext HTTP GET/POST with a URI longer than 1024 characters to a private management-style HTTP port. This does not identify an embedded asset, exploit string, vulnerable application, or exploit success.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R709_PublicOversizedManagementHttpRequestRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R710 — Private host UDP/11211 fanout to three public peers</strong> · Medium</summary>

- **Description:** One private source sends coherent UDP datagrams to Memcached port 11211 on three distinct public peers within 60 seconds. This is an amplification-shaped fanout only; source spoofing, Memcached command semantics, reflection, victim traffic, and denial-of-service impact are not observed.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R710_PublicMemcachedUdpFanoutRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R716 — SIPROTEC-shaped 18-byte UDP/50000 fanout to private devices</strong> · Medium</summary>

- **Description:** One source sends 18-byte UDP payloads to diagnostic port 50000 on two distinct private devices within 60 seconds. This is a narrow SIPROTEC/Industroyer-shaped packet pattern only; restart service semantics, device identity, authorization, offline state, and impact are unverified.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R716_SiprotecDiagnosticUdpFanoutRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R728 — Node runtime connection attempt to private OT service</strong> · Medium</summary>

- **Description:** node or nodejs is associated with a TCP SYN to a private OT service port. Parent process, script path, user, approved asset role, application payload and device outcome are not observed.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R728_NodeRuntimePrivateOtServiceSynRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R729 — Python runtime connection attempt to private OT service</strong> · Medium</summary>

- **Description:** python or python3 is associated with a TCP SYN to a private OT service port. Script path, parent process, user, approved automation role, application payload and device outcome are not observed.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R729_PythonRuntimePrivateOtServiceSynRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R730 — Unix shell connection attempt to private OT service</strong> · Medium</summary>

- **Description:** bash, sh, ash, zsh, or busybox is associated with a TCP SYN to a private OT service port. Parent process, command line, remote-session origin, asset role, application payload and device outcome are not observed.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R730_UnixShellPrivateOtServiceSynRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R771 — Public-source SNMP/161 query burst to private host</strong> · Medium</summary>

- **Description:** A public source sends twelve coherent UDP/161 observations to one private host within ten seconds. SNMP GETBULK/GETNEXT semantics, community strings, authentication state, exact OIDs and MIB-dump completion are not observed.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R771_PublicSnmpQueryBurstToPrivateHostRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R772 — High-rate payload traffic to private OT service</strong> · Medium</summary>

- **Description:** Twenty payload-bearing TCP/UDP observations target one private OT-associated service port within ten seconds. Malformed PDU semantics, approved-controller identity, poll failure, device resource exhaustion, service degradation and denial-of-service impact are not observed.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R772_PrivateOtServicePayloadFloodShapeRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R946 — Private TFTP initial request then matched first response</strong> · Medium</summary>

- **Description:** Private parsed TFTP RRQ or WRQ followed by the exact capture-correlated DATA block 1 or ACK block 0 within 45 seconds. Transfer completion, filename, firmware and authorization are unknown.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R946_PrivateTftpRequestThenEphemeralReplyRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R947 — Private SSH ingress then public parsed TFTP request</strong> · Medium</summary>

- **Description:** Private TCP/22 SYN to a host followed by a capture-attested public TFTP RRQ or WRQ from that host. SSH authentication, ROMMON change, firmware and transfer completion are unknown.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R947_PrivateSshIngressThenPublicTftpRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R948 — Private FTP STOR then same-peer SSH SYN</strong> · Medium</summary>

- **Description:** Private parsed FTP STOR request followed by same-source same-destination TCP/22 SYN. File name, upload completion, SCP, firmware role, boot configuration and authorization are unknown.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R948_PrivateFtpStorThenSshSynRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R949 — Private FTP STOR then same-peer parsed TFTP request</strong> · Medium</summary>

- **Description:** Private parsed FTP STOR followed by capture-attested TFTP RRQ or WRQ to the same peer. File identity, successful upload, firmware and authorization are unknown.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R949_PrivateFtpStorThenTftpDataRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R960 — Private SSH-port payload cadence with local tool attribution</strong> · Medium</summary>

- **Description:** Same private ssh/plink PID and private peer sends four TCP/22 data records of 512–4096 bytes at 5–20 second intervals. ICS role, approved management baseline, decoded SSH command and authorization are unknown.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R960_PrivateSshPortPayloadCadenceRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R961 — Public proxy-port ingress then private Modbus SYN</strong> · Medium</summary>

- **Description:** Public TCP/3128 SYN to a private host followed by that host sending TCP/502 SYN to a private peer in a different /24. Proxy relay, VLAN policy, device role, authentication and control action are unknown.
- **Category:** IotOtAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R961_PublicProxyIngressThenPrivateModbusSynRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### IPv6: 6 rules

<details>
<summary>Choose a rule from 6 IPv6 entries</summary>

<details>
<summary><strong>R067 — Rogue IPv6 Router Advertisement</strong> · High</summary>

- **Description:** Corroborated router-advertisement source identity change; does not establish authorization.
- **Category:** IPv6
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IPv6/R067_RogueIPv6RouterAdvertisementRule.cs)
- **Detailed evidence and test scenarios:** [066-070](batches/RULE_BATCH_066-070.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R068 — IPv6 Neighbor Discovery Sweep</strong> · Medium</summary>

- **Description:** Distinct unicast ICMPv6 neighbor solicitations in a bounded configured window.
- **Category:** IPv6
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IPv6/R068_IPv6NeighborDiscoverySweepRule.cs)
- **Detailed evidence and test scenarios:** [066-070](batches/RULE_BATCH_066-070.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R069 — IPv6 Duplicate Address / Spoofing</strong> · High</summary>

- **Description:** Corroborated conflicting IPv6 neighbor-advertisement identity; not proof of spoofing.
- **Category:** IPv6
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IPv6/R069_IPv6DuplicateAddressSpoofingRule.cs)
- **Detailed evidence and test scenarios:** [066-070](batches/RULE_BATCH_066-070.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R070 — Teredo / 6to4 / ISATAP Tunnel Use</strong> · Medium</summary>

- **Description:** Corroborated IPv6 transition-protocol use, not a policy-violation verdict.
- **Category:** IPv6
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IPv6/R070_Teredo6to4ISATAPTunnelUseRule.cs)
- **Detailed evidence and test scenarios:** [066-070](batches/RULE_BATCH_066-070.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R071 — IPv6 Traffic on IPv4-Only Network</strong> · Medium</summary>

- **Description:** Two corroborated IPv6 flows under explicitly approved IPv4-only policy.
- **Category:** IPv6
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IPv6/R071_IPv6TrafficOnIPv4OnlyNetworkRule.cs)
- **Detailed evidence and test scenarios:** [071-075](batches/RULE_BATCH_071-075.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R072 — Suspicious Multicast Discovery Burst</strong> · Medium</summary>

- **Description:** Bounded structured IPv6 mDNS, LLMNR or SSDP discovery burst.
- **Category:** IPv6
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/IPv6/R072_SuspiciousMulticastDiscoveryBurstRule.cs)
- **Detailed evidence and test scenarios:** [071-075](batches/RULE_BATCH_071-075.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### KubernetesContainer: 20 rules

<details>
<summary>Choose a rule from 20 KubernetesContainer entries</summary>

<details>
<summary><strong>R293 — Kubernetes Anonymous API Discovery Probe</strong> · High</summary>

- **Description:** Detects Kubernetes Anonymous API Discovery Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R293_KubernetesAnonymousAPIDiscoveryProbeRule.cs)
- **Detailed evidence and test scenarios:** [291-295](batches/RULE_BATCH_291-295.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R294 — Kubernetes Secrets API Access Probe</strong> · Critical</summary>

- **Description:** Detects Kubernetes Secrets API Access Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R294_KubernetesSecretsAPIAccessProbeRule.cs)
- **Detailed evidence and test scenarios:** [291-295](batches/RULE_BATCH_291-295.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R295 — Kubernetes Exec Into Pod Over API</strong> · Critical</summary>

- **Description:** Detects Kubernetes Exec Into Pod Over API only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R295_KubernetesExecIntoPodOverAPIRule.cs)
- **Detailed evidence and test scenarios:** [291-295](batches/RULE_BATCH_291-295.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R296 — Kubernetes PortForward Abuse Indicator</strong> · High</summary>

- **Description:** Detects Kubernetes PortForward Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R296_KubernetesPortForwardAbuseIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [296-300](batches/RULE_BATCH_296-300.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R297 — Kubernetes ServiceAccount Token Exfil</strong> · Critical</summary>

- **Description:** Detects Kubernetes ServiceAccount Token Exfil only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R297_KubernetesServiceAccountTokenExfilRule.cs)
- **Detailed evidence and test scenarios:** [296-300](batches/RULE_BATCH_296-300.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R298 — Container Runtime Socket Exposure Probe</strong> · Critical</summary>

- **Description:** Detects Container Runtime Socket Exposure Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R298_ContainerRuntimeSocketExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [296-300](batches/RULE_BATCH_296-300.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R299 — Docker Remote API Container Create</strong> · Critical</summary>

- **Description:** Detects Docker Remote API Container Create only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R299_DockerRemoteAPIContainerCreateRule.cs)
- **Detailed evidence and test scenarios:** [296-300](batches/RULE_BATCH_296-300.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R300 — Kubernetes Etcd Client Access External</strong> · Critical</summary>

- **Description:** Detects Kubernetes Etcd Client Access External only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R300_KubernetesEtcdClientAccessExternalRule.cs)
- **Detailed evidence and test scenarios:** [296-300](batches/RULE_BATCH_296-300.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R301 — Kubelet Readonly Port Probe</strong> · High</summary>

- **Description:** Detects Kubelet Readonly Port Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R301_KubeletReadonlyPortProbeRule.cs)
- **Detailed evidence and test scenarios:** [301-305](batches/RULE_BATCH_301-305.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R302 — Kubelet Run Or Exec Probe</strong> · Critical</summary>

- **Description:** Detects Kubelet Run Or Exec Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R302_KubeletRunOrExecProbeRule.cs)
- **Detailed evidence and test scenarios:** [301-305](batches/RULE_BATCH_301-305.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R303 — Container Registry Manifest Enumeration</strong> · Medium</summary>

- **Description:** Detects Container Registry Manifest Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R303_ContainerRegistryManifestEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [301-305](batches/RULE_BATCH_301-305.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R304 — Container Registry Anonymous Pull Burst</strong> · Medium</summary>

- **Description:** Detects Container Registry Anonymous Pull Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R304_ContainerRegistryAnonymousPullBurstRule.cs)
- **Detailed evidence and test scenarios:** [301-305](batches/RULE_BATCH_301-305.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R305 — Image Registry Push From Workstation</strong> · High</summary>

- **Description:** Detects Image Registry Push From Workstation only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R305_ImageRegistryPushFromWorkstationRule.cs)
- **Detailed evidence and test scenarios:** [301-305](batches/RULE_BATCH_301-305.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R306 — Docker Build Context Archive Upload</strong> · High</summary>

- **Description:** Detects Docker Build Context Archive Upload only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R306_DockerBuildContextArchiveUploadRule.cs)
- **Detailed evidence and test scenarios:** [306-310](batches/RULE_BATCH_306-310.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R307 — Kubernetes Dashboard Exposure Probe</strong> · High</summary>

- **Description:** Detects Kubernetes Dashboard Exposure Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R307_KubernetesDashboardExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [306-310](batches/RULE_BATCH_306-310.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R308 — Helm Tiller Legacy Port Exposure</strong> · High</summary>

- **Description:** Detects Helm Tiller Legacy Port Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R308_HelmTillerLegacyPortExposureRule.cs)
- **Detailed evidence and test scenarios:** [306-310](batches/RULE_BATCH_306-310.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R309 — Istio Envoy Admin Endpoint Probe</strong> · High</summary>

- **Description:** Detects Istio Envoy Admin Endpoint Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R309_IstioEnvoyAdminEndpointProbeRule.cs)
- **Detailed evidence and test scenarios:** [306-310](batches/RULE_BATCH_306-310.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R310 — Service Mesh Sidecar Bypass Pattern</strong> · Medium</summary>

- **Description:** Detects Service Mesh Sidecar Bypass Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R310_ServiceMeshSidecarBypassPatternRule.cs)
- **Detailed evidence and test scenarios:** [306-310](batches/RULE_BATCH_306-310.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R311 — Cloud Workload Metadata Token Request</strong> · Critical</summary>

- **Description:** Detects Cloud Workload Metadata Token Request only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R311_CloudWorkloadMetadataTokenRequestRule.cs)
- **Detailed evidence and test scenarios:** [311-315](batches/RULE_BATCH_311-315.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R312 — Kubernetes Network Policy Bypass Indicator</strong> · High</summary>

- **Description:** Detects Kubernetes Network Policy Bypass Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** KubernetesContainer
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R312_KubernetesNetworkPolicyBypassIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [311-315](batches/RULE_BATCH_311-315.md)
- **Verification record:** 0 executed (reported)

</details>

</details>

### Lateral Movement: 1 rules

<details>
<summary>Choose a rule from 1 Lateral Movement entries</summary>

<details>
<summary><strong>R030 — Internal Admin Lateral Sweep</strong> · High</summary>

- **Description:** Internal admin lateral sweep
- **Category:** Lateral Movement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R030_InternalAdminLateralSweepRule.cs)
- **Detailed evidence and test scenarios:** [026-030](batches/RULE_BATCH_026-030.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### LateralMovement: 45 rules

<details>
<summary>Choose a rule from 45 LateralMovement entries</summary>

<details>
<summary><strong>R073 — RDPLateral Movement Burst</strong> · High</summary>

- **Description:** Distinct internal TCP initiations with typed service evidence; authorization not inferred.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R073_RDPLateralMovementBurstRule.cs)
- **Detailed evidence and test scenarios:** [071-075](batches/RULE_BATCH_071-075.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R074 — Win RMPower Shell Remoting Sweep</strong> · High</summary>

- **Description:** Distinct internal TCP initiations with typed service evidence; authorization not inferred.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R074_WinRMPowerShellRemotingSweepRule.cs)
- **Detailed evidence and test scenarios:** [071-075](batches/RULE_BATCH_071-075.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R075 — WMIDCOMLateral Movement</strong> · High</summary>

- **Description:** Distinct internal TCP initiations with typed service evidence; authorization not inferred.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R075_WMIDCOMLateralMovementRule.cs)
- **Detailed evidence and test scenarios:** [071-075](batches/RULE_BATCH_071-075.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R076 — SMB Admin Share Access Pattern</strong> · High</summary>

- **Description:** Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R076_SMBAdminShareAccessPatternRule.cs)
- **Detailed evidence and test scenarios:** [076-080](batches/RULE_BATCH_076-080.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R077 — RPC Service Control Pattern</strong> · High</summary>

- **Description:** Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R077_RPCServiceControlPatternRule.cs)
- **Detailed evidence and test scenarios:** [076-080](batches/RULE_BATCH_076-080.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R078 — PsExec-Like Network Behavior</strong> · Critical</summary>

- **Description:** Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.
- **Category:** LateralMovement
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R078_PsExecLikeNetworkBehaviorRule.cs)
- **Detailed evidence and test scenarios:** [076-080](batches/RULE_BATCH_076-080.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R079 — LDAP Enumeration Spike</strong> · High</summary>

- **Description:** Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R079_LDAPEnumerationSpikeRule.cs)
- **Detailed evidence and test scenarios:** [076-080](batches/RULE_BATCH_076-080.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R080 — Kerberos TGS Request Spike</strong> · High</summary>

- **Description:** Attributable typed lateral-movement telemetry; authorization and operator intent not inferred.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R080_KerberosTGSRequestSpikeRule.cs)
- **Detailed evidence and test scenarios:** [076-080](batches/RULE_BATCH_076-080.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R081 — AS-REP Roasting Heuristic</strong> · High</summary>

- **Description:** Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R081_ASREPRoastingHeuristicRule.cs)
- **Detailed evidence and test scenarios:** [081-085](batches/RULE_BATCH_081-085.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R082 — NTLM Relay Suspicion</strong> · High</summary>

- **Description:** Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R082_NTLMRelaySuspicionRule.cs)
- **Detailed evidence and test scenarios:** [081-085](batches/RULE_BATCH_081-085.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R083 — LLMNR / NBNS Poisoning Attempt</strong> · High</summary>

- **Description:** Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.
- **Category:** LateralMovement
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/LateralMovement/R083_LLMNRNBNSPoisoningAttemptRule.cs)
- **Detailed evidence and test scenarios:** [081-085](batches/RULE_BATCH_081-085.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R665 — Explorer WebDAV-like GET followed by SMB SYN to same public peer</strong> · Medium</summary>

- **Description:** Explorer WebDAV-like GET followed by SMB SYN to same public peer. R174 observes inbound WebDAV abuse; R351 requires NTLM-attributed telemetry. This candidate observes only two ordered outbound network attempts, never credential coercion.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R665_ExplorerWebDavThenExternalSmbSynSequenceRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R754 — macOS-style transfer tool private-peer payload burst</strong> · Medium</summary>

- **Description:** scp, sftp, or rsync is associated with four substantial TCP payload observations to one private peer on port 22 or 873 within two minutes. File identity, remote authentication, transfer direction, unique bytes, execution on the destination and lateral compromise are not observed.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R754_MacTransferToolPrivatePeerPayloadBurstRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R755 — Public VNC attempt followed by macOS-style script egress</strong> · Medium</summary>

- **Description:** A public-to-private TCP SYN to VNC/5900 is followed within 90 seconds by outbound public traffic from the same private host attributed to osascript, zsh, curl, or python3. VNC authentication, exploit success, process parentage, service crash, causal linkage and compromise are not observed.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R755_PublicVncAttemptThenMacScriptEgressRule.cs)
- **Detailed evidence and test scenarios:** [746-755](batches/RULE_BATCH_746-755.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R757 — LLMNR/NBNS conflicting response followed by SMB connection to responder</strong> · Medium</summary>

- **Description:** A parser-corroborated unicast conflicting LLMNR/NBNS response from one private host is followed within 60 seconds by a TCP SYN from the same peer to that responder on SMB/445. Credential interception, NTLM relay classification, authentication and compromise are not observed.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R757_LlmnrNbnsConflictThenSmbRelayShapeRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R765 — Public Linux-service attempt followed by shell/tool egress</strong> · Medium</summary>

- **Description:** A public-to-private TCP SYN to a common Linux remote/service port is followed within 90 seconds by outbound public traffic from the same private host attributed to bash, sh, zsh, curl, wget, Python or Python3. Service crash, shell parentage, successful login/exploit, causal linkage and compromise are not observed.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R765_LinuxRemoteServiceAttemptThenShellEgressRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R775 — macOS SSH listener response followed by user-tool egress</strong> · Medium</summary>

- **Description:** An sshd-attributed private-host TCP/22 SYN-ACK to a public client is followed within ninety seconds by outbound public traffic from the same host attributed to zsh, osascript, curl, or python3. Login success, user identity, process parentage, interactive shell state, causality and compromise are not observed.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R775_MacSshdPublicSynAckThenUserToolEgressRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R789 — Net-process SMB2 write request followed by TCP FIN</strong> · Medium</summary>

- **Description:** Net-process SMB2 write request followed by TCP FIN. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R789_NetProcessSmbWriteThenFinRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R791 — Public administrative HTTP POST then local curl TLS egress</strong> · Medium</summary>

- **Description:** Public administrative HTTP POST then local curl TLS egress. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R791_PublicAdminPostThenCurlEgressRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R794 — Internal proxy-port SYN followed by relay SYN into a third subnet</strong> · Medium</summary>

- **Description:** Internal proxy-port SYN followed by relay SYN into a third subnet. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R794_InterSubnetRelayToAdminPortRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R807 — Public SSH service reply followed by local east-west SSH SYN</strong> · Medium</summary>

- **Description:** Public SSH service reply followed by local east-west SSH SYN. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R807_PublicSshServiceThenEastWestSshRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R836 — PostgreSQL inbound SYN then service-attributed public TLS</strong> · Medium</summary>

- **Description:** Public inbound TCP/5432 SYN followed by postgres-attributed TLS/8443 outbound from same private host; no SQL COPY PROGRAM, process execution or transfer proven.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R836_PostgresInboundThenServiceTlsRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R845 — scp-attributed payloads to two internal SSH subnets</strong> · Medium</summary>

- **Description:** Same local scp PID sends TCP payload on port22 to hosts in two distinct private /24 subnets within 60s; no file transfer completion or ESXi-specific proof.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R845_ScpDistinctInternalSshPeersRule.cs)
- **Detailed evidence and test scenarios:** [836-845](batches/RULE_BATCH_836-845.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R850 — Public OpenSLP ingress SYN then internal SSH SYN</strong> · Medium</summary>

- **Description:** A public TCP SYN targets private OpenSLP/427, followed by that private host initiating an internal TCP/22 SYN within 60s; no ESXi identity or exploitation proven.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R850_PublicOpenSlpThenInternalSshSynRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R851 — Public SSH ingress SYN then local shell public SYN</strong> · Medium</summary>

- **Description:** Incoming public TCP/22 SYN followed by locally attributed bash/sh outbound public TCP/8443 SYN on same private host; SSH login, shell lineage and execution not proven.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R851_PublicSshIngressThenShellPublicSynRule.cs)
- **Detailed evidence and test scenarios:** [846-855](batches/RULE_BATCH_846-855.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R859 — Public SSH ingress then esxcli-attributed TLS egress</strong> · Medium</summary>

- **Description:** Public SSH/22 inbound SYN then esxcli-attributed public TLS/8443 from same private host within 60s; no login, host role or command proven.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R859_PublicSshIngressThenEsxcliPublicTlsRule.cs)
- **Detailed evidence and test scenarios:** [856-865](batches/RULE_BATCH_856-865.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R869 — Public RPC 135 SYN followed by dynamic-port SYN to same host</strong> · Medium</summary>

- **Description:** One public client sends SYN to a private RPC endpoint on TCP/135 then to the same host on a dynamic RPC-like port within 45s; no DCOM invocation, login, process creation or execution is proven.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R869_PublicRpcEndpointThenDynamicPortRule.cs)
- **Detailed evidence and test scenarios:** [866-875](batches/RULE_BATCH_866-875.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R879 — Public Telnet SYN then busybox-attributed public TLS</strong> · Medium</summary>

- **Description:** Public TCP/23 SYN to private host precedes busybox-attributed TLS/8443 egress from that host within 60s; Telnet login, shell execution, process causality and device role are not established.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R879_PublicTelnetThenBusyboxTlsRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R881 — Public FTP control SYN then private parsed TFTP WRQ</strong> · Medium</summary>

- **Description:** Public TCP/21 SYN to a private host precedes that host&#x27;s capture-attested TFTP WRQ to another private device within 60s; file identity, actual transfer and file placement are unobserved.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R881_PublicFtpThenPrivateTftpRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R886 — Public SSH SYN followed by private SMB SYN</strong> · Medium</summary>

- **Description:** Public SSH SYN into a private host followed by that host initiating private SMB/445 SYN within 60s; no SSH login, interactive shell, privilege escalation or lateral success is proved.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R886_SshIngressThenInternalSmbSynRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R892 — Private broadcast UDP/9 then RDP SYN from same source</strong> · Medium</summary>

- **Description:** Private source sends broadcast-address UDP/9 payload sized 102 bytes then SYNs to a private RDP/3389 peer within 45s; magic-packet bytes, host wake, firewall change and successful RDP are not decoded.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R892_BroadcastUdpNineThenRdpSynRule.cs)
- **Detailed evidence and test scenarios:** [886-895](batches/RULE_BATCH_886-895.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R903 — PowerShell private SMB2 WRITE then WinRM SYN</strong> · Medium</summary>

- **Description:** Same private source and PowerShell PID send a parsed SMB2 WRITE request to TCP/445 then a TCP/5985 SYN to that private peer within 45s; file creation, transfer completion, authenticated WinRM and execution are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R903_PowershellSmbWriteThenWinRmSynRule.cs)
- **Detailed evidence and test scenarios:** [901-905](batches/RULE_BATCH_901-905.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R906 — Rundll32 public SMB SYN then same-flow data</strong> · Medium</summary>

- **Description:** Rundll32-associated TCP/445 SYN then TCP data on the same public peer and source port. Remote DLL path, execution and authentication are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R906_Rundll32PublicSmbSynThenDataRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R908 — Public SMB SYN then same-flow parsed WRITE</strong> · Medium</summary>

- **Description:** Public TCP/445 SYN to private host followed by parsed SMB2 WRITE on the same source port. Admin share, account, filename and write success are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R908_PublicSmbSynThenParsedWriteRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R909 — Private SSH ingress then public RDP SYN</strong> · Medium</summary>

- **Description:** Private TCP/22 SYN to a private host followed by that host sending TCP/3389 SYN to a public peer. Bastion role, login and authorization are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R909_PrivateSshIngressThenPublicRdpSynRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R910 — PowerShell private LDAP SYN then SMB2 WRITE</strong> · Medium</summary>

- **Description:** Same private source, PowerShell PID and private peer TCP/389 SYN then parsed SMB2 WRITE. GPO object, SYSVOL path, authentication and modification are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R910_PowershellLdapSynThenSmbWriteRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R911 — Rsync private TCP/873 data to three peers</strong> · Medium</summary>

- **Description:** Same private source and rsync PID sends TCP/873 data to three distinct private peers. File, arguments, authorization and execution are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R911_RsyncPrivatePeerDataFanoutRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R912 — Public SSH SYN then BusyBox private rsync-port data</strong> · Medium</summary>

- **Description:** Public SSH SYN to private host then BusyBox TCP/873 data from that host to a private peer. Shell execution, SSH authentication and transfer are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R912_PublicSshThenBusyboxPrivateRsyncRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R917 — Private RDP ingress then private WinRM SYN</strong> · Medium</summary>

- **Description:** Private TCP/3389 SYN to private host followed by that host sending TCP/5985 SYN to another private peer. ICS role, approved matrix, login and execution are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R917_PrivateRdpThenOtherHostWinRmSynRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R918 — PowerShell private Modbus WRITE then public TLS</strong> · Medium</summary>

- **Description:** Same private source and PowerShell PID sends parsed private Modbus write request then public TLS/443 data. Script, OT role, authorization and write outcome are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R918_PowershellModbusWriteThenPublicTlsRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R919 — PsExec private SMB2 WRITE then RPC SYN</strong> · Medium</summary>

- **Description:** Same private source, PsExec PID and private peer parsed SMB2 WRITE then TCP/135 SYN. Named pipe, service creation, account and execution are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R919_PsexecSmbWriteThenRpcSynRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R924 — Public RDP SYN then private SMB SYN from target</strong> · Medium</summary>

- **Description:** Public TCP/3389 SYN to private host followed by that host sending TCP/445 SYN to a private peer. Authentication, sessions and lateral compromise are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R924_PublicRdpThenPrivateSmbSynRule.cs)
- **Detailed evidence and test scenarios:** [906-925](batches/RULE_BATCH_906-925.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R931 — NTLMRelayx private SMB then LDAP SYN</strong> · Medium</summary>

- **Description:** Same private source and ntlmrelayx PID contacts private SMB/445 then LDAP/389 on another or same private peer. Credential relay, authentication and privilege changes are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R931_NtlmrelayxPrivateSmbThenLdapSynRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R942 — Private SMB2 WRITE then Modbus SYN</strong> · Medium</summary>

- **Description:** Private source sends a parsed SMB2 WRITE to a private host followed by that host initiating TCP/502 SYN to another private peer. File extension, execution, OT asset role and successful control action are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R942_PrivateSmbWriteThenModbusSynRule.cs)
- **Detailed evidence and test scenarios:** [926-945](batches/RULE_BATCH_926-945.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R950 — PowerShell private PS1 GET then parsed SMB2 WRITE</strong> · Medium</summary>

- **Description:** Same private PowerShell PID retrieves a .ps1 path over private HTTP then issues a parsed SMB2 WRITE to the same private peer. GPO, logon script setting, file contents, user logon and execution are unknown.
- **Category:** LateralMovement
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R950_PowershellPrivateScriptGetThenSmbWriteRule.cs)
- **Detailed evidence and test scenarios:** [946-965](batches/RULE_BATCH_946-965.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### LocalDiscoveryWireless: 21 rules

<details>
<summary>Choose a rule from 21 LocalDiscoveryWireless entries</summary>

<details>
<summary><strong>R453 — mDNS Service Enumeration High Rate</strong> · Medium</summary>

- **Description:** Detects mDNS Service Enumeration High Rate only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R453_MDNSServiceEnumerationHighRateRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R454 — SSDP MSEARCH External Answer</strong> · Medium</summary>

- **Description:** Detects SSDP MSEARCH External Answer only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R454_SSDPMSEARCHExternalAnswerRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R455 — AirPlay Discovery From Non Media Host</strong> · Low</summary>

- **Description:** Detects AirPlay Discovery From Non Media Host only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R455_AirPlayDiscoveryFromNonMediaHostRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R456 — Chromecast Discovery Burst</strong> · Low</summary>

- **Description:** Detects Chromecast Discovery Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R456_ChromecastDiscoveryBurstRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R457 — Printer JetDirect External Access</strong> · Medium</summary>

- **Description:** Detects Printer JetDirect External Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R457_PrinterJetDirectExternalAccessRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R458 — IPP Printing From External Host</strong> · Medium</summary>

- **Description:** Detects IPP Printing From External Host only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R458_IPPPrintingFromExternalHostRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R459 — SMB Browse Election Anomaly</strong> · Low</summary>

- **Description:** Detects SMB Browse Election Anomaly only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R459_SMBBrowseElectionAnomalyRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R460 — NetBIOS Name Query Sweep</strong> · Medium</summary>

- **Description:** Detects NetBIOS Name Query Sweep only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R460_NetBIOSNameQuerySweepRule.cs)
- **Detailed evidence and test scenarios:** [451-460](batches/RULE_BATCH_451-460.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R461 — DHCP Starvation Candidate</strong> · High</summary>

- **Description:** Detects DHCP Starvation Candidate only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R461_DHCPStarvationCandidateRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R462 — DHCP Rogue Offer Detected</strong> · High</summary>

- **Description:** Detects DHCP Rogue Offer Detected only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R462_DHCPRogueOfferDetectedRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R463 — ARP Gratuitous Storm</strong> · Medium</summary>

- **Description:** Detects ARP Gratuitous Storm only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R463_ARPGratuitousStormRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R464 — ARP Duplicate MAC FlipFlop</strong> · High</summary>

- **Description:** Detects ARP Duplicate MAC FlipFlop only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R464_ARPDuplicateMACFlipFlopRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R465 — IPv6 SLAAC Prefix Change</strong> · Medium</summary>

- **Description:** Detects IPv6 SLAAC Prefix Change only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R465_IPv6SLAACPrefixChangeRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R466 — WiFi Controller Admin Probe</strong> · High</summary>

- **Description:** Detects WiFi Controller Admin Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R466_WiFiControllerAdminProbeRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R467 — CAPWAP External Controller Attempt</strong> · High</summary>

- **Description:** Detects CAPWAP External Controller Attempt only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R467_CAPWAPExternalControllerAttemptRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R468 — Bluetooth Gateway Internet Egress</strong> · Medium</summary>

- **Description:** Detects Bluetooth Gateway Internet Egress only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R468_BluetoothGatewayInternetEgressRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R469 — Android Debug Bridge Network Access</strong> · High</summary>

- **Description:** Detects Android Debug Bridge Network Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R469_AndroidDebugBridgeNetworkAccessRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R470 — Mobile MDM Enrollment Burst</strong> · Medium</summary>

- **Description:** Detects Mobile MDM Enrollment Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R470_MobileMDMEnrollmentBurstRule.cs)
- **Detailed evidence and test scenarios:** [461-470](batches/RULE_BATCH_461-470.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R471 — RDP Clipboard File Transfer Indicator</strong> · Medium</summary>

- **Description:** Detects RDP Clipboard File Transfer Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R471_RDPClipboardFileTransferIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R472 — Remote Support Tool Unexpected Use</strong> · Medium</summary>

- **Description:** Detects Remote Support Tool Unexpected Use only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R472_RemoteSupportToolUnexpectedUseRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R707 — Two distinct private DHCP responders target one client</strong> · Medium</summary>

- **Description:** Two distinct private source addresses send coherent UDP/67-to-68 datagrams to the same private client within 10 seconds. The packets are not parsed as DHCP OFFER/ACK and do not establish rogue-server status or malicious DNS/gateway options.
- **Category:** LocalDiscoveryWireless
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R707_CompetingDhcpResponderDatagramsRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### MalwareC2: 20 rules

<details>
<summary>Choose a rule from 20 MalwareC2 entries</summary>

<details>
<summary><strong>R393 — Cobalt Strike Beacon URI Pattern</strong> · Critical</summary>

- **Description:** Detects Cobalt Strike Beacon URI Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R393_CobaltStrikeBeaconURIPatternRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R394 — Cobalt Strike Malleable C2 Header Pattern</strong> · Critical</summary>

- **Description:** Detects Cobalt Strike Malleable C2 Header Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R394_CobaltStrikeMalleableC2HeaderPatternRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R395 — Sliver C2 MTLS Pattern</strong> · Critical</summary>

- **Description:** Detects Sliver C2 MTLS Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R395_SliverC2MTLSPatternRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R396 — Mythic Agent Callback Pattern</strong> · High</summary>

- **Description:** Detects Mythic Agent Callback Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R396_MythicAgentCallbackPatternRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R397 — Metasploit Meterpreter Stager Pattern</strong> · Critical</summary>

- **Description:** Detects Metasploit Meterpreter Stager Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R397_MetasploitMeterpreterStagerPatternRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R398 — Havoc C2 Callback Pattern</strong> · Critical</summary>

- **Description:** Detects Havoc C2 Callback Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R398_HavocC2CallbackPatternRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R399 — Brute Ratel Badger Pattern</strong> · Critical</summary>

- **Description:** Detects Brute Ratel Badger Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R399_BruteRatelBadgerPatternRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R400 — Covenant Grunt Callback Pattern</strong> · High</summary>

- **Description:** Detects Covenant Grunt Callback Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R400_CovenantGruntCallbackPatternRule.cs)
- **Detailed evidence and test scenarios:** [391-400](batches/RULE_BATCH_391-400.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R401 — Empire Stager URI Pattern</strong> · High</summary>

- **Description:** Detects Empire Stager URI Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R401_EmpireStagerURIPatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R402 — AsyncRAT Telegram C2 Pattern</strong> · Critical</summary>

- **Description:** Detects AsyncRAT Telegram C2 Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R402_AsyncRATTelegramC2PatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R403 — Remcos RAT C2 Pattern</strong> · Critical</summary>

- **Description:** Detects Remcos RAT C2 Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R403_RemcosRATC2PatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R404 — AgentTesla SMTP Exfil Pattern</strong> · Critical</summary>

- **Description:** Detects AgentTesla SMTP Exfil Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R404_AgentTeslaSMTPExfilPatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R405 — QakBot URI Pattern</strong> · High</summary>

- **Description:** Detects QakBot URI Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R405_QakBotURIPatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R406 — Emotet Loader URI Pattern</strong> · High</summary>

- **Description:** Detects Emotet Loader URI Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R406_EmotetLoaderURIPatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R407 — Bumblebee Loader URI Pattern</strong> · High</summary>

- **Description:** Detects Bumblebee Loader URI Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R407_BumblebeeLoaderURIPatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R408 — SocGholish FakeUpdate Pattern</strong> · High</summary>

- **Description:** Detects SocGholish FakeUpdate Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R408_SocGholishFakeUpdatePatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R409 — Raspberry Robin Short LNK Pattern</strong> · Medium</summary>

- **Description:** Detects Raspberry Robin Short LNK Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R409_RaspberryRobinShortLNKPatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R410 — Redline Stealer Exfil Pattern</strong> · Critical</summary>

- **Description:** Detects Redline Stealer Exfil Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R410_RedlineStealerExfilPatternRule.cs)
- **Detailed evidence and test scenarios:** [401-410](batches/RULE_BATCH_401-410.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R411 — Lumma Stealer Gate Pattern</strong> · Critical</summary>

- **Description:** Detects Lumma Stealer Gate Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R411_LummaStealerGatePatternRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R412 — Generic Beacon Jitter Low Variance</strong> · Medium</summary>

- **Description:** Detects Generic Beacon Jitter Low Variance only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** MalwareC2
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R412_GenericBeaconJitterLowVarianceRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Network: 10 rules

<details>
<summary>Choose a rule from 10 Network entries</summary>

<details>
<summary><strong>R001 — Port Scan</strong> · Low</summary>

- **Description:** Port scan against multiple destination ports
- **Category:** Network
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R001_PortScanRule.cs)
- **Detailed evidence and test scenarios:** [001-005](batches/RULE_BATCH_001-005.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R002 — Flood / DoS</strong> · Low</summary>

- **Description:** Flood or denial-of-service behavior
- **Category:** Network
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R002_FloodDosRule.cs)
- **Detailed evidence and test scenarios:** [001-005](batches/RULE_BATCH_001-005.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R011 — DHCP Abuse</strong> · Low</summary>

- **Description:** Suspicious DHCP activity
- **Category:** Network
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R011_DhcpAbuseRule.cs)
- **Detailed evidence and test scenarios:** [011-015](batches/RULE_BATCH_011-015.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R013 — Uncommon Ports / Service-Port Anomaly</strong> · Low</summary>

- **Description:** Unexpected service-port pairing
- **Category:** Network
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R013_UncommonPortsServicePortAnomalyRule.cs)
- **Detailed evidence and test scenarios:** [011-015](batches/RULE_BATCH_011-015.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R015 — ARP Spoofing</strong> · Low</summary>

- **Description:** Potential ARP spoofing
- **Category:** Network
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R015_ArpSpoofingRule.cs)
- **Detailed evidence and test scenarios:** [011-015](batches/RULE_BATCH_011-015.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R731 — Windows network-tool outbound SYN/UDP flood shape</strong> · Medium</summary>

- **Description:** PowerShell, cmd, or curl is associated with twelve outbound SYN or small UDP observations to one public peer/port within ten seconds. CPU exhaustion, interface throughput, victim impact, spoofing and denial of service are not observed.
- **Category:** Network
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R731_WindowsNetworkToolOutboundFloodShapeRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R732 — Linux network-tool outbound SYN/UDP flood shape</strong> · Medium</summary>

- **Description:** bash, sh, python, curl, or wget is associated with twelve outbound SYN or small UDP observations to one public peer/port within ten seconds. Kernel throughput, resource exhaustion, spoofing, victim impact and denial of service are not observed.
- **Category:** Network
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R732_LinuxNetworkToolOutboundFloodShapeRule.cs)
- **Detailed evidence and test scenarios:** [726-735](batches/RULE_BATCH_726-735.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R739 — Linux script/CLI cleartext HTTP request flood</strong> · Medium</summary>

- **Description:** curl, wget, Python, or Python3 produces twelve parsed cleartext HTTP GET/POST requests to one public peer within ten seconds. Backend CPU/memory exhaustion, worker spawning, server errors and denial-of-service impact are not observed.
- **Category:** Network
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R739_LinuxScriptHttpRequestFloodRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R745 — hping/nping rapid public-target SYN fanout</strong> · Medium</summary>

- **Description:** hping3, hping, or nping produces TCP SYNs to four distinct public targets within ten seconds. Packet rate beyond the observed threshold, source spoofing, victim impact and denial-of-service outcome are not observed.
- **Category:** Network
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R745_HpingNpingPublicTargetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [736-745](batches/RULE_BATCH_736-745.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R768 — osascript outbound SYN/UDP flood shape</strong> · Medium</summary>

- **Description:** osascript is associated with twelve outbound TCP SYN or small UDP observations to one public peer and port within ten seconds. UI context, packet-generator command line, throughput, spoofing, victim impact and denial-of-service outcome are not observed.
- **Category:** Network
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R768_OsascriptOutboundFloodShapeRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### NetworkApplianceExposure: 21 rules

<details>
<summary>Choose a rule from 21 NetworkApplianceExposure entries</summary>

<details>
<summary><strong>R413 — Citrix Netscaler Gateway Scan Pattern</strong> · High</summary>

- **Description:** Detects Citrix Netscaler Gateway Scan Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R413_CitrixNetscalerGatewayScanPatternRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R414 — Ivanti Connect Secure Exploit Probe</strong> · High</summary>

- **Description:** Detects Ivanti Connect Secure Exploit Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R414_IvantiConnectSecureExploitProbeRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R415 — F5 BIG-IP TMUI Probe</strong> · High</summary>

- **Description:** Detects F5 BIG-IP TMUI Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R415_F5BIGIPTMUIProbeRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R416 — SonicWall SSLVPN Exploit Probe</strong> · High</summary>

- **Description:** Detects SonicWall SSLVPN Exploit Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R416_SonicWallSSLVPNExploitProbeRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R417 — Cisco ASA WebVPN Probe</strong> · High</summary>

- **Description:** Detects Cisco ASA WebVPN Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R417_CiscoASAWebVPNProbeRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R418 — MikroTik Winbox External Access</strong> · High</summary>

- **Description:** Detects MikroTik Winbox External Access only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R418_MikroTikWinboxExternalAccessRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R419 — Ubiquiti Discovery External Exposure</strong> · Medium</summary>

- **Description:** Detects Ubiquiti Discovery External Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R419_UbiquitiDiscoveryExternalExposureRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R420 — QNAP QTS Admin Probe</strong> · High</summary>

- **Description:** Detects QNAP QTS Admin Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R420_QNAPQTSAdminProbeRule.cs)
- **Detailed evidence and test scenarios:** [411-420](batches/RULE_BATCH_411-420.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R421 — Synology DSM Admin Probe</strong> · High</summary>

- **Description:** Detects Synology DSM Admin Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R421_SynologyDSMAdminProbeRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R422 — VMware vCenter SOAP Probe</strong> · High</summary>

- **Description:** Detects VMware vCenter SOAP Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R422_VMwareVCenterSOAPProbeRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R423 — VMware ESXi Hostd Probe</strong> · High</summary>

- **Description:** Detects VMware ESXi Hostd Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R423_VMwareESXiHostdProbeRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R424 — Proxmox API Exposure Probe</strong> · High</summary>

- **Description:** Detects Proxmox API Exposure Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R424_ProxmoxAPIExposureProbeRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R425 — Apache Solr Admin Probe</strong> · High</summary>

- **Description:** Detects Apache Solr Admin Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R425_ApacheSolrAdminProbeRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R426 — Elasticsearch Cluster Info External</strong> · High</summary>

- **Description:** Detects Elasticsearch Cluster Info External only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R426_ElasticsearchClusterInfoExternalRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R427 — Kibana Console Exposure</strong> · High</summary>

- **Description:** Detects Kibana Console Exposure only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R427_KibanaConsoleExposureRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R428 — Grafana Admin Login Probe</strong> · Medium</summary>

- **Description:** Detects Grafana Admin Login Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R428_GrafanaAdminLoginProbeRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R429 — Prometheus Metrics Exposure External</strong> · Medium</summary>

- **Description:** Detects Prometheus Metrics Exposure External only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R429_PrometheusMetricsExposureExternalRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R430 — Jupyter Notebook Token Probe</strong> · High</summary>

- **Description:** Detects Jupyter Notebook Token Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R430_JupyterNotebookTokenProbeRule.cs)
- **Detailed evidence and test scenarios:** [421-430](batches/RULE_BATCH_421-430.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R431 — Airflow Admin Endpoint Probe</strong> · High</summary>

- **Description:** Detects Airflow Admin Endpoint Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R431_AirflowAdminEndpointProbeRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R432 — Consul Nomad Admin Probe</strong> · High</summary>

- **Description:** Detects Consul Nomad Admin Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** NetworkApplianceExposure
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R432_ConsulNomadAdminProbeRule.cs)
- **Detailed evidence and test scenarios:** [431-440](batches/RULE_BATCH_431-440.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R659 — Public client probing SNMP, NETCONF, and HTTPS management ports</strong> · Medium</summary>

- **Description:** Public client probing SNMP, NETCONF, and HTTPS management ports. R585 tracks a triad of parsed administrative operations, not this exact cross-transport SNMP/NETCONF/HTTPS port triad.
- **Category:** NetworkApplianceExposure
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R659_PublicManagementPortTriadToPrivateDeviceRule.cs)
- **Detailed evidence and test scenarios:** [656-665](batches/RULE_BATCH_656-665.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### NetworkDiscovery: 7 rules

<details>
<summary>Choose a rule from 7 NetworkDiscovery entries</summary>

<details>
<summary><strong>R676 — Unicast–broadcast–network-address TCP SYN signaling sequence</strong> · Low</summary>

- **Description:** Unicast–broadcast–network-address TCP SYN signaling sequence; No firewall activation, router change, magic packet acceptance or SSH session is observed.
- **Category:** NetworkDiscovery
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R676_UnicastBroadcastNetworkAddressSynKnockRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R678 — Sequential three-host internal-subnet ICMP echo discovery</strong> · Low</summary>

- **Description:** Sequential three-host internal-subnet ICMP echo discovery; No full network scan, unauthorized discovery or ARP probe is inferred.
- **Category:** NetworkDiscovery
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R678_SequentialInternalSubnetIcmpEchoWalkRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R714 — Netcat process probes four ports on one private peer</strong> · Low</summary>

- **Description:** One best-effort Netcat/Ncat PID sends SYNs to four distinct ports on the same private peer within 30 seconds. This is a service-discovery-shaped probe only; container context, vulnerability state, connect success, and lateral movement are not observed.
- **Category:** NetworkDiscovery
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R714_NetcatInternalMultiPortProbeRule.cs)
- **Detailed evidence and test scenarios:** [706-715](batches/RULE_BATCH_706-715.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R724 — Network utility contact to public-IP discovery service</strong> · Low</summary>

- **Description:** Curl, Wget, or PowerShell is associated with an outbound HTTP/TLS contact to a bounded public-IP discovery service. The user&#x27;s intent, shell command, returned public IP, subsequent behavior, and malicious purpose are not observed.
- **Category:** NetworkDiscovery
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R724_NetworkUtilityPublicIpDiscoveryServiceRule.cs)
- **Detailed evidence and test scenarios:** [716-725](batches/RULE_BATCH_716-725.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R819 — public config-export API GET then private host public parsed TFTP WRQ egress</strong> · Medium</summary>

- **Description:** public config-export API GET then private host public parsed TFTP WRQ egress. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** NetworkDiscovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R819_PublicConfigExportGetThenTftpEgressRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R824 — ping-attributed ICMP echo to three distinct public hosts</strong> · Medium</summary>

- **Description:** ping-attributed ICMP echo to three distinct public hosts. Source-only network/process evidence; no authorization, compromise or successful outcome inferred.
- **Category:** NetworkDiscovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R824_PingProcessPublicIcmpTargetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R827 — finger.exe SYNs to three distinct public finger services</strong> · Medium</summary>

- **Description:** Process-attributed TCP/79 SYN fanout only; the original process-execution signal and remote username lookups are not observed.
- **Category:** NetworkDiscovery
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R827_FingerPublicTargetFanoutRule.cs)
- **Detailed evidence and test scenarios:** [826-835](batches/RULE_BATCH_826-835.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### OtIcsDeep: 21 rules

<details>
<summary>Choose a rule from 21 OtIcsDeep entries</summary>

<details>
<summary><strong>R473 — Modbus Function43 DeviceId Enumeration</strong> · Medium</summary>

- **Description:** Detects Modbus Function43 DeviceId Enumeration only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R473_ModbusFunction43DeviceIdEnumerationRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R474 — Modbus Force Listen Only Mode Attempt</strong> · Critical</summary>

- **Description:** Detects Modbus Force Listen Only Mode Attempt only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R474_ModbusForceListenOnlyModeAttemptRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R475 — Modbus Diagnostics Function Abuse</strong> · High</summary>

- **Description:** Detects Modbus Diagnostics Function Abuse only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R475_ModbusDiagnosticsFunctionAbuseRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R476 — Modbus Coil Write Burst</strong> · Critical</summary>

- **Description:** Detects Modbus Coil Write Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R476_ModbusCoilWriteBurstRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R477 — S7 Start Stop CPU Command Indicator</strong> · Critical</summary>

- **Description:** Detects S7 Start Stop CPU Command Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R477_S7StartStopCPUCommandIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R478 — S7 Upload Download Block Transfer</strong> · Critical</summary>

- **Description:** Detects S7 Upload Download Block Transfer only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R478_S7UploadDownloadBlockTransferRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R479 — S7 PLC Identification Probe</strong> · Medium</summary>

- **Description:** Detects S7 PLC Identification Probe only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R479_S7PLCIdentificationProbeRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R480 — DNP3 Control Relay Output Block</strong> · Critical</summary>

- **Description:** Detects DNP3 Control Relay Output Block only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R480_DNP3ControlRelayOutputBlockRule.cs)
- **Detailed evidence and test scenarios:** [471-480](batches/RULE_BATCH_471-480.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R481 — DNP3 Freeze Counter Command</strong> · High</summary>

- **Description:** Detects DNP3 Freeze Counter Command only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R481_DNP3FreezeCounterCommandRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R482 — IEC104 Control Command External</strong> · Critical</summary>

- **Description:** Detects IEC104 Control Command External only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R482_IEC104ControlCommandExternalRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R483 — OPC UA Browse Node Burst</strong> · Medium</summary>

- **Description:** Detects OPC UA Browse Node Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R483_OPCUABrowseNodeBurstRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R484 — OPC UA Write Request Indicator</strong> · Critical</summary>

- **Description:** Detects OPC UA Write Request Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R484_OPCUAWriteRequestIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R485 — BACnet WriteProperty Request</strong> · Critical</summary>

- **Description:** Shadow-only candidate for a validated BACnet/IP unsegmented confirmed WriteProperty request crossing a trust boundary; no device modification claimed.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R485_BACnetWritePropertyRequestRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R486 — BACnet DeviceCommunicationControl</strong> · Critical</summary>

- **Description:** Shadow-only candidate for a captured unsegmented BACnet/IP DeviceCommunicationControl disable request crossing a trust boundary; controller outcome unknown.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R486_BACnetDeviceCommunicationControlRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R487 — Profinet DCP Set Name Request</strong> · High</summary>

- **Description:** Detects Profinet DCP Set Name Request only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R487_ProfinetDCPSetNameRequestRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R488 — EtherNetIP ListIdentity Burst</strong> · Medium</summary>

- **Description:** Detects EtherNetIP ListIdentity Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R488_EtherNetIPListIdentityBurstRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R489 — EtherNetIP ForwardOpen External</strong> · Critical</summary>

- **Description:** Detects EtherNetIP ForwardOpen External only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R489_EtherNetIPForwardOpenExternalRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R490 — IEC61850 MMS Write Indicator</strong> · Critical</summary>

- **Description:** Detects IEC61850 MMS Write Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R490_IEC61850MMSWriteIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [481-490](batches/RULE_BATCH_481-490.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R491 — GOOSE Multicast Outside Substation</strong> · Critical</summary>

- **Description:** Detects GOOSE Multicast Outside Substation only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R491_GOOSEMulticastOutsideSubstationRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R492 — Historian Bulk Query From Workstation</strong> · High</summary>

- **Description:** Detects Historian Bulk Query From Workstation only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.
- **Category:** OtIcsDeep
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R492_HistorianBulkQueryFromWorkstationRule.cs)
- **Detailed evidence and test scenarios:** [491-500](batches/RULE_BATCH_491-500.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R643 — Sequential EtherNet/IP ListIdentity private-subnet discovery walk</strong> · Medium</summary>

- **Description:** Sequential EtherNet/IP ListIdentity private-subnet discovery walk. Observed evidence only; Does not establish PLC identity, authorized engineer inventory, full subnet scan or unauthorized access. Capture can miss packets and suppress a true walk.
- **Category:** OtIcsDeep
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R643_SequentialEtherNetIpListIdentitySubnetWalkRule.cs)
- **Detailed evidence and test scenarios:** [636-645](batches/RULE_BATCH_636-645.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Payload: 1 rules

<details>
<summary>Choose a rule from 1 Payload entries</summary>

<details>
<summary><strong>R014 — Cleartext Credentials</strong> · Low</summary>

- **Description:** Cleartext credential exposure
- **Category:** Payload
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R014_CleartextCredentialsRule.cs)
- **Detailed evidence and test scenarios:** [011-015](batches/RULE_BATCH_011-015.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Payloads: 10 rules

<details>
<summary>Choose a rule from 10 Payloads entries</summary>

<details>
<summary><strong>R084 — Log4Shell / JNDI Injection Pattern</strong> · Critical</summary>

- **Description:** Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.
- **Category:** Payloads
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R084_Log4ShellJNDIInjectionPatternRule.cs)
- **Detailed evidence and test scenarios:** [081-085](batches/RULE_BATCH_081-085.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R085 — SQL Injection Pattern</strong> · High</summary>

- **Description:** Attributable typed protocol or structured HTTP evidence; no free-text Info-based detection.
- **Category:** Payloads
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R085_SQLInjectionPatternRule.cs)
- **Detailed evidence and test scenarios:** [081-085](batches/RULE_BATCH_081-085.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R086 — Path Traversal / LFI Pattern</strong> · High</summary>

- **Description:** Structured request evidence only; does not establish execution or malicious intent.
- **Category:** Payloads
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R086_PathTraversalLFIPatternRule.cs)
- **Detailed evidence and test scenarios:** [086-090](batches/RULE_BATCH_086-090.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R087 — Webshell Upload Pattern</strong> · Critical</summary>

- **Description:** Structured request evidence only; does not establish execution or malicious intent.
- **Category:** Payloads
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R087_WebshellUploadPatternRule.cs)
- **Detailed evidence and test scenarios:** [086-090](batches/RULE_BATCH_086-090.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R088 — Suspicious Deserialization Payload</strong> · High</summary>

- **Description:** Structured request evidence only; does not establish execution or malicious intent.
- **Category:** Payloads
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R088_SuspiciousDeserializationPayloadRule.cs)
- **Detailed evidence and test scenarios:** [086-090](batches/RULE_BATCH_086-090.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R089 — Command Injection Pattern</strong> · High</summary>

- **Description:** Structured request evidence only; does not establish execution or malicious intent.
- **Category:** Payloads
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R089_CommandInjectionPatternRule.cs)
- **Detailed evidence and test scenarios:** [086-090](batches/RULE_BATCH_086-090.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R090 — Reverse Shell Payload Indicator</strong> · Critical</summary>

- **Description:** Structured request evidence only; does not establish execution or malicious intent.
- **Category:** Payloads
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R090_ReverseShellPayloadIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [086-090](batches/RULE_BATCH_086-090.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R091 — Nmap / Masscan / Zgrab User-Agent</strong> · High</summary>

- **Description:** Only structured, attributable HTTP evidence can raise a candidate; raw packet notes are excluded.
- **Category:** Payloads
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R091_NmapMasscanZgrabUserAgentRule.cs)
- **Detailed evidence and test scenarios:** [091-095](batches/RULE_BATCH_091-095.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R092 — Known Malware HTTP URI Pattern</strong> · Critical</summary>

- **Description:** Only structured, attributable HTTP evidence can raise a candidate; raw packet notes are excluded.
- **Category:** Payloads
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R092_KnownMalwareHTTPURIPatternRule.cs)
- **Detailed evidence and test scenarios:** [091-095](batches/RULE_BATCH_091-095.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R093 — Suspicious PowerShell Download Cradle over HTTP</strong> · High</summary>

- **Description:** Only structured, attributable HTTP evidence can raise a candidate; raw packet notes are excluded.
- **Category:** Payloads
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Payloads/R093_SuspiciousPowerShellDownloadCradleOverHTTPRule.cs)
- **Detailed evidence and test scenarios:** [091-095](batches/RULE_BATCH_091-095.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### PlatformHealthAdvanced: 16 rules

<details>
<summary>Choose a rule from 16 PlatformHealthAdvanced entries</summary>

<details>
<summary><strong>R529 — Sensor Heartbeat Missing For Site</strong> · High</summary>

- **Description:** Detects explicit health-monitor telemetry showing that a site/sensor heartbeat is missing or overdue; it never infers absence from a single traffic record.
- **Category:** PlatformHealthAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R529_SensorHeartbeatMissingForSiteRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R530 — Sensor Clock Skew Increasing</strong> · Medium</summary>

- **Description:** Detects explicit sensor clock-skew drift reported by platform health telemetry.
- **Category:** PlatformHealthAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R530_SensorClockSkewIncreasingRule.cs)
- **Detailed evidence and test scenarios:** [521-530](batches/RULE_BATCH_521-530.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R531 — Detection Journal Disk Space Low</strong> · Critical</summary>

- **Description:** Detects explicit low-disk/low-free-space telemetry for the detection journal path.
- **Category:** PlatformHealthAdvanced
- **Severity:** Critical
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R531_DetectionJournalDiskSpaceLowRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R532 — Outbox Retry Storm</strong> · High</summary>

- **Description:** Detects a concrete Carthago outbox retry storm only when platform-health telemetry explicitly references outbox retry/backoff/failure behavior; ordinary network retries do not match.
- **Category:** PlatformHealthAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R532_OutboxRetryStormRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R533 — Rule Match Volume Anomaly</strong> · Medium</summary>

- **Description:** Detects explicit rule-match volume anomalies emitted by the rule engine, requiring rule identity plus spike/surge/regression semantics.
- **Category:** PlatformHealthAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R533_RuleMatchVolumeAnomalyRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R534 — Rule Silent Unexpectedly</strong> · Medium</summary>

- **Description:** Detects explicit platform telemetry that a rule stopped matching despite expected telemetry/baseline activity; absence is accepted only from a health monitor, never inferred from one packet.
- **Category:** PlatformHealthAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R534_RuleSilentUnexpectedlyRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R535 — Telemetry Field Coverage Drop</strong> · High</summary>

- **Description:** Detects explicit field-coverage degradation from telemetry health checks, requiring coverage/drop/missing-field semantics.
- **Category:** PlatformHealthAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R535_TelemetryFieldCoverageDropRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R536 — Parser Error Spike</strong> · High</summary>

- **Description:** Detects parser-error spikes only from explicit parser/platform-health telemetry or repeated parser failure events in a short window.
- **Category:** PlatformHealthAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R536_ParserErrorSpikeRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R537 — GeoIP Lookup Failure Spike</strong> · Low</summary>

- **Description:** Detects GeoIP enrichment failure spikes from explicit platform-health telemetry, not from ordinary missing country fields.
- **Category:** PlatformHealthAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R537_GeoIPLookupFailureSpikeRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R538 — Reputation Lookup Failure Spike</strong> · Low</summary>

- **Description:** Detects reputation/enrichment lookup failure spikes from explicit health telemetry.
- **Category:** PlatformHealthAdvanced
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R538_ReputationLookupFailureSpikeRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R539 — Baseline Store Write Failure</strong> · High</summary>

- **Description:** Detects concrete baseline persistence/write failures reported by the baseline subsystem.
- **Category:** PlatformHealthAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R539_BaselineStoreWriteFailureRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R540 — Feedback Store Write Failure</strong> · Medium</summary>

- **Description:** Detects concrete analyst-feedback persistence/write failures reported by the feedback subsystem.
- **Category:** PlatformHealthAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R540_FeedbackStoreWriteFailureRule.cs)
- **Detailed evidence and test scenarios:** [531-540](batches/RULE_BATCH_531-540.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R541 — Content Pack Validation Failure</strong> · Medium</summary>

- **Description:** Detects schema, signature, duplicate-ID, or compatibility validation failures when loading rule/content packs.
- **Category:** PlatformHealthAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R541_ContentPackValidationFailureRule.cs)
- **Detailed evidence and test scenarios:** [541-544](batches/RULE_BATCH_541-544.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R542 — Replay Benchmark Regression</strong> · High</summary>

- **Description:** Detects explicit replay-benchmark precision/recall/performance regressions emitted by the test/replay subsystem.
- **Category:** PlatformHealthAdvanced
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R542_ReplayBenchmarkRegressionRule.cs)
- **Detailed evidence and test scenarios:** [541-544](batches/RULE_BATCH_541-544.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R543 — Rule Config Profile Drift</strong> · Medium</summary>

- **Description:** Detects explicit drift between expected rule precision/config profile and the active runtime profile.
- **Category:** PlatformHealthAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R543_RuleConfigProfileDriftRule.cs)
- **Detailed evidence and test scenarios:** [541-544](batches/RULE_BATCH_541-544.md)
- **Verification record:** 0 executed (reported)

</details>

<details>
<summary><strong>R544 — Excessive Suppression Ratio</strong> · Medium</summary>

- **Description:** Detects explicit rule-engine telemetry showing that suppression ratio exceeded an expected threshold for a rule or scope.
- **Category:** PlatformHealthAdvanced
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R544_ExcessiveSuppressionRatioRule.cs)
- **Detailed evidence and test scenarios:** [541-544](batches/RULE_BATCH_541-544.md)
- **Verification record:** 0 executed (reported)

</details>

</details>

### Protocol: 1 rules

<details>
<summary>Choose a rule from 1 Protocol entries</summary>

<details>
<summary><strong>R005 — Suspicious Protocol</strong> · Low</summary>

- **Description:** Suspicious or unexpected protocol usage
- **Category:** Protocol
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R005_SuspiciousProtocolRule.cs)
- **Detailed evidence and test scenarios:** [001-005](batches/RULE_BATCH_001-005.md)
- **Verification record:** See historical verification record

</details>

</details>

### ProtocolIntelligence: 1 rules

<details>
<summary>Choose a rule from 1 ProtocolIntelligence entries</summary>

<details>
<summary><strong>R811 — Repeated expired remote TLS certificates on service port 9443</strong> · Medium</summary>

- **Description:** Repeated expired remote TLS certificates on service port 9443. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** ProtocolIntelligence
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R811_ExpiredCertificateUnusualTlsPortRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### QUIC: 2 rules

<details>
<summary>Choose a rule from 2 QUIC entries</summary>

<details>
<summary><strong>R029 — QUIC Anomaly</strong> · Low</summary>

- **Description:** QUIC anomaly detected
- **Category:** QUIC
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R029_QuicAnomalyRule.cs)
- **Detailed evidence and test scenarios:** [026-030](batches/RULE_BATCH_026-030.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R042 — Uncommon QUIC ALPN</strong> · Low</summary>

- **Description:** Uncommon QUIC ALPN
- **Category:** QUIC
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R042_UncommonQuicAlpnRule.cs)
- **Detailed evidence and test scenarios:** [041-045](batches/RULE_BATCH_041-045.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Reconnaissance: 1 rules

<details>
<summary>Choose a rule from 1 Reconnaissance entries</summary>

<details>
<summary><strong>R017 — Internal Host Sweep</strong> · Low</summary>

- **Description:** Internal host sweep behavior
- **Category:** Reconnaissance
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R017_InternalHostSweepRule.cs)
- **Detailed evidence and test scenarios:** [016-020](batches/RULE_BATCH_016-020.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### RemoteAccess: 2 rules

<details>
<summary>Choose a rule from 2 RemoteAccess entries</summary>

<details>
<summary><strong>R761 — RMM process recurrent external TLS cadence</strong> · Medium</summary>

- **Description:** TeamViewer, AnyDesk, or ScreenConnect/ConnectWise Control process attribution is associated with three similarly sized TLS/443 payload observations to one public peer at 10–60 second intervals. Installation, firewall changes, session establishment, operator identity and malicious use are not observed.
- **Category:** RemoteAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R761_RmmProcessExternalTlsCadenceRule.cs)
- **Detailed evidence and test scenarios:** [756-765](batches/RULE_BATCH_756-765.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R774 — macOS screensharingd public VNC SYN-ACK</strong> · Medium</summary>

- **Description:** screensharingd is associated with a private-host TCP/5900 SYN-ACK to a public client. Unified-log login evidence, authentication, remote-control session establishment, user interaction and authorization are not observed.
- **Category:** RemoteAccess
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R774_MacScreensharingdPublicVncSynAckRule.cs)
- **Detailed evidence and test scenarios:** [766-775](batches/RULE_BATCH_766-775.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### SSH: 1 rules

<details>
<summary>Choose a rule from 1 SSH entries</summary>

<details>
<summary><strong>R035 — Rare SSH Client Fingerprint</strong> · Low</summary>

- **Description:** Rare SSH client fingerprint
- **Category:** SSH
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R035_RareSshClientFingerprintRule.cs)
- **Detailed evidence and test scenarios:** [031-035](batches/RULE_BATCH_031-035.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### Threat Intel: 2 rules

<details>
<summary>Choose a rule from 2 Threat Intel entries</summary>

<details>
<summary><strong>R003 — Threat Feed Hit</strong> · High</summary>

- **Description:** Traffic matched threat feed intelligence
- **Category:** Threat Intel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R003_ThreatFeedHitRule.cs)
- **Detailed evidence and test scenarios:** [001-005](batches/RULE_BATCH_001-005.md)
- **Verification record:** See historical verification record

</details>

<details>
<summary><strong>R016 — Reputation / AbuseIPDB</strong> · High</summary>

- **Description:** Destination reputation match
- **Category:** Threat Intel
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R016_ReputationAbuseIpdbRule.cs)
- **Detailed evidence and test scenarios:** [016-020](batches/RULE_BATCH_016-020.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### TLS: 8 rules

<details>
<summary>Choose a rule from 8 TLS entries</summary>

<details>
<summary><strong>R012 — Suspicious TLS</strong> · Medium</summary>

- **Description:** Suspicious TLS behavior
- **Category:** TLS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R012_SuspiciousTlsRule.cs)
- **Detailed evidence and test scenarios:** [011-015](batches/RULE_BATCH_011-015.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R023 — TLS to Public IP Without SNI</strong> · Medium</summary>

- **Description:** TLS to public IP without SNI
- **Category:** TLS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R023_TlsToPublicIpWithoutSniRule.cs)
- **Detailed evidence and test scenarios:** [021-025](batches/RULE_BATCH_021-025.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R024 — Rare / Novel TLS Fingerprint</strong> · Medium</summary>

- **Description:** Rare TLS fingerprint
- **Category:** TLS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R024_RareNovelTlsFingerprintRule.cs)
- **Detailed evidence and test scenarios:** [021-025](batches/RULE_BATCH_021-025.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R025 — TLS Certificate Expired or Expiring Soon</strong> · Medium</summary>

- **Description:** TLS certificate expiry risk
- **Category:** TLS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R025_TlsCertificateExpiredOrExpiringSoonRule.cs)
- **Detailed evidence and test scenarios:** [021-025](batches/RULE_BATCH_021-025.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R037 — JA4 Drift per SNI</strong> · Medium</summary>

- **Description:** JA4 drift for an SNI
- **Category:** TLS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R037_Ja4DriftPerSniRule.cs)
- **Detailed evidence and test scenarios:** [036-040](batches/RULE_BATCH_036-040.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R040 — Long-Lived Low-Throughput Encrypted Session</strong> · Medium</summary>

- **Description:** Long-lived low-throughput encrypted session
- **Category:** TLS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R040_LongLivedLowThroughputEncryptedSessionRule.cs)
- **Detailed evidence and test scenarios:** [036-040](batches/RULE_BATCH_036-040.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R041 — JA4 Fan-Out Sweep</strong> · Medium</summary>

- **Description:** JA4 fan-out sweep
- **Category:** TLS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R041_Ja4FanOutSweepRule.cs)
- **Detailed evidence and test scenarios:** [041-045](batches/RULE_BATCH_041-045.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R049 — Suspicious SNI Shape</strong> · Medium</summary>

- **Description:** Suspicious SNI shape
- **Category:** TLS
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Existing/R049_SuspiciousSniShapeRule.cs)
- **Detailed evidence and test scenarios:** [046-050](batches/RULE_BATCH_046-050.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### TlsPki: 17 rules

<details>
<summary>Choose a rule from 17 TlsPki entries</summary>

<details>
<summary><strong>R138 — Self-Signed Certificate To External Host</strong> · Medium</summary>

- **Description:** Flags external TLS certificates with identical issuer and subject distinguished names; this is a self-issued indicator, not cryptographic proof of a self-signature.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R138_SelfSignedCertificateToExternalHostRule.cs)
- **Detailed evidence and test scenarios:** [136-140](batches/RULE_BATCH_136-140.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R139 — Weak TLS Version Observed</strong> · High</summary>

- **Description:** Detects actual TLS 1.0, TLS 1.1, or SSLv3 usage from parsed TLS version metadata.
- **Category:** TlsPki
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R139_WeakTlsVersionObservedRule.cs)
- **Detailed evidence and test scenarios:** [136-140](batches/RULE_BATCH_136-140.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R140 — Suspicious Certificate Issuer Pattern</strong> · Medium</summary>

- **Description:** Detects TLS certificates whose issuer string matches suspicious local, test, or interception patterns.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R140_SuspiciousCertificateIssuerPatternRule.cs)
- **Detailed evidence and test scenarios:** [136-140](batches/RULE_BATCH_136-140.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R141 — New SNI With Rare TLS Fingerprint</strong> · Medium</summary>

- **Description:** Detects repeated external TLS sessions where a non-browser fingerprint repeatedly reaches the same SNI in a short window.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R141_NewSniWithRareTlsFingerprintRule.cs)
- **Detailed evidence and test scenarios:** [141-145](batches/RULE_BATCH_141-145.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R142 — TLS Certificate Subject SNI Mismatch</strong> · Medium</summary>

- **Description:** Detects strong SNI-to-certificate-subject mismatches for external TLS sessions.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R142_TlsCertificateSubjectSniMismatchRule.cs)
- **Detailed evidence and test scenarios:** [141-145](batches/RULE_BATCH_141-145.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R143 — Wildcard Certificate On Sensitive Service</strong> · Medium</summary>

- **Description:** Detects wildcard certificate subjects on sensitive non-web TLS service ports.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R143_WildcardCertificateOnSensitiveServiceRule.cs)
- **Detailed evidence and test scenarios:** [141-145](batches/RULE_BATCH_141-145.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R144 — Certificate Validity Period Too Long</strong> · Medium</summary>

- **Description:** Detects external TLS certificates whose validity period is unusually long.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R144_CertificateValidityPeriodTooLongRule.cs)
- **Detailed evidence and test scenarios:** [141-145](batches/RULE_BATCH_141-145.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R145 — Short-Lived Certificate With New SNI</strong> · Medium</summary>

- **Description:** Detects repeated external TLS sessions where a non-browser fingerprint reaches the same SNI using a very short-lived certificate.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R145_ShortLivedCertificateWithNewSniRule.cs)
- **Detailed evidence and test scenarios:** [141-145](batches/RULE_BATCH_141-145.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R146 — TLS Handshake Failure Spike</strong> · Medium</summary>

- **Description:** Detects thresholded spikes of TLS handshake failures for the same source and destination.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R146_TlsHandshakeFailureSpikeRule.cs)
- **Detailed evidence and test scenarios:** [146-150](batches/RULE_BATCH_146-150.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R147 — Encrypted ClientHello Or ECH Indicator</strong> · Low</summary>

- **Description:** Detects explicit ECH or Encrypted ClientHello indicators only when real TLS context is present.
- **Category:** TlsPki
- **Severity:** Low
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R147_EncryptedClienthelloOrEchIndicatorRule.cs)
- **Detailed evidence and test scenarios:** [146-150](batches/RULE_BATCH_146-150.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R148 — TLS To Dynamic DNS Host</strong> · Medium</summary>

- **Description:** Detects external TLS sessions to hosted subdomains on dynamic-DNS providers, while suppressing provider root sites and browser noise.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R148_TlsToDynamicDnsHostRule.cs)
- **Detailed evidence and test scenarios:** [146-150](batches/RULE_BATCH_146-150.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R149 — IP Literal Used As TLS Name</strong> · Medium</summary>

- **Description:** Detects TLS sessions that explicitly use an IP literal as the SNI name.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R149_IpLiteralUsedAsTlsNameRule.cs)
- **Detailed evidence and test scenarios:** [146-150](batches/RULE_BATCH_146-150.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R150 — Known Malware-Like TLS Fingerprint Label</strong> · High</summary>

- **Description:** Detects TLS telemetry that includes a parsed JA3 or JA4 fingerprint plus an explicit malware-family style label.
- **Category:** TlsPki
- **Severity:** High
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R150_KnownMalwareLikeTlsFingerprintLabelRule.cs)
- **Detailed evidence and test scenarios:** [146-150](batches/RULE_BATCH_146-150.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R151 — HTTP2 ALPN On Uncommon Port</strong> · Medium</summary>

- **Description:** Detects non-browser external TLS sessions that negotiate HTTP/2 ALPN on uncommon ports.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R151_Http2AlpnOnUncommonPortRule.cs)
- **Detailed evidence and test scenarios:** [151-155](batches/RULE_BATCH_151-155.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R152 — TLS Fingerprint Fan-Out To Many ASNs</strong> · Medium</summary>

- **Description:** Detects non-browser external TLS fingerprints that fan out to many distinct ASNs in a short window.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R152_TlsFingerprintFanOutToManyAsnsRule.cs)
- **Detailed evidence and test scenarios:** [151-155](batches/RULE_BATCH_151-155.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R669 — System binary TLS ClientHello on nominal HTTP port 80</strong> · Medium</summary>

- **Description:** System binary TLS ClientHello on nominal HTTP port 80. No TLS cert validation, server authentication, or protocol impersonation proof.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R669_SystemBinaryTlsClientOnCleartextPort80Rule.cs)
- **Detailed evidence and test scenarios:** [666-675](batches/RULE_BATCH_666-675.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R677 — Outbound TLS observation on DNS port 53 or alternate HTTP port 8080</strong> · Medium</summary>

- **Description:** Outbound TLS observation on DNS port 53 or alternate HTTP port 8080; Unusual TLS port alone does not establish a tunnel, certificate abuse or encrypted C2.
- **Category:** TlsPki
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R677_TlsClientHelloOnDnsOrAltHttpPortRule.cs)
- **Detailed evidence and test scenarios:** [676-685](batches/RULE_BATCH_676-685.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### WebAttack: 1 rules

<details>
<summary>Choose a rule from 1 WebAttack entries</summary>

<details>
<summary><strong>R795 — Large public HTTP POST burst to firmware upload endpoint</strong> · Medium</summary>

- **Description:** Large public HTTP POST burst to firmware upload endpoint. A bounded observation only; no config change, successful authentication, transfer, exploitation or compromise established.
- **Category:** WebAttack
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R795_PublicManagementUploadPostBurstRule.cs)
- **Detailed evidence and test scenarios:** [786-795](batches/RULE_BATCH_786-795.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

### WebThreat: 3 rules

<details>
<summary>Choose a rule from 3 WebThreat entries</summary>

<details>
<summary><strong>R809 — Public client login POST followed by portal administration POST</strong> · Medium</summary>

- **Description:** Public client login POST followed by portal administration POST. Observable packet/process shape only; no authorization, causality, success or compromise inferred.
- **Category:** WebThreat
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R809_PublicLoginThenPortalAdminPostRule.cs)
- **Detailed evidence and test scenarios:** [806-815](batches/RULE_BATCH_806-815.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R825 — Public image upload POST then matching served-path GET</strong> · Medium</summary>

- **Description:** Public image-upload POST followed by same-source matching served-path GET. No file modification, defacement or upload success inferred.
- **Category:** WebThreat
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R825_PublicWebUploadThenServedGetRule.cs)
- **Detailed evidence and test scenarios:** [816-825](batches/RULE_BATCH_816-825.md)
- **Verification record:** Candidate — unverified (reported)

</details>

<details>
<summary><strong>R880 — Public CGI traversal GET followed by admin upload POST</strong> · Medium</summary>

- **Description:** One public client sends GET to /cgi-bin/.%2e/ followed by POST to /admin/upload on same private web host within 45s; no server error, upload, spawned process or exploit success is observed.
- **Category:** WebThreat
- **Severity:** Medium
- **Enabled by default:** true
- **Implementation:** [C# source](../../Carthago/Engine/Rules/Expansion/R880_PublicTraversalThenAdminPostRule.cs)
- **Detailed evidence and test scenarios:** [876-885](batches/RULE_BATCH_876-885.md)
- **Verification record:** Candidate — unverified (reported)

</details>

</details>

## Evidence coverage notes

Every registered rule maps to at least one historical batch page. That is evidence of documentation coverage only, not validation.

**Refresh:** run `python3 scripts/build_rule_catalog.py` from the repository root after a rule GA, followed by `python3 scripts/build_docs_index.py` and the static `python3 scripts/check_docs_links.py` inspection. This is source-only and does not run Carthago tests.
