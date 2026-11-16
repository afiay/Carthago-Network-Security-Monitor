# Rule qualification resume ledger

**Current registry reconciliation (2026-11-16): 1,000 registered core IDs.** See [current reconciliation](../05-detection-quality/REGISTRY_RECONCILIATION_20261116.md) and [all 1,000 exact IDs](../05-detection-quality/registry-reconciliation.csv). The following 965-rule baseline and associated 717/248/35 totals are historical, not current readiness or execution counts.

Baseline audit: `6a677b73a1db687961413ba440e4eb283e822d89` (965 registered, 717 historical covered, 248 gaps, 35 remaining). Historical Windows regression 12,354/12,354; not a claim about new source. Catalog/source review pinned to `6eca564e4681d70c1a6d03a1e074545c9dd8c2f6`. All rows inherit this source SHA; update individual rows with a new SHA when inspected. Initial membership is provisional, not a verified live coverage count. No tests executed.

Columns: rule, catalog implementation path, required producer, positive evidence/test path, negative evidence/test path, boundary evidence/test path, status/blocker. Pending means not yet independently inspected, not absent. Do not promote a row without actual detector tests and supported producer evidence.

| Rule | Implementation | Producer | Positive | Negative | Boundary | Status/blocker |
|---|---|---|---|---|---|---|
| R270 | Carthago/Engine/Rules/Expansion/R270_DetectionPipelineTamperingIndicatorRule.cs | trusted control-plane change and authorization/maintenance evidence | unavailable: unconditional NoMatch | pending | pending | producer-blocked at 1d810357c0f7e64ff6956dfab4329155ce2c8a85; packet text/process names cannot establish tampering; distinguish authorized maintenance and ordinary failure from unauthorized change |
| R271 | Carthago/Engine/Rules/Expansion/R271_ThreatFeedIocWithLowReputationOverlapRule.cs | exact source-IP feed + independent reputation; snapshot-consistent match/time | helper-only per historical progress; detector test pending | pending | pending | source reviewed 800a2b3a421d04909c2a4b48d30e437cd7cf4654; snapshot race corrected; reputation provenance and detector fixture pending |
| R272 | Carthago/Engine/Rules/Expansion/R272_MultiSignalRuleStackSurgeFromHostRule.cs | engine post-policy emitted signals, read-only host/time snapshot in Carthago/Engine/RuleEngine.Core.cs | Carthago.Tests/R272AdvancedAccuracyBatchTests.cs (engine R014/R026/R031 emissions, host isolation, public context, reset; authored/unexecuted) | two-family, repeated FTP packet, host isolation, public context, reset, mutated source (authored/unexecuted) | exact window, future/expired, mapped alias cooldown, snapshot immutability (authored/unexecuted) | source candidate 04117bbd4c5dc7592b6161dec743936a99ae3d1c; three distinct rules and categories, ten-minute window, replay reset; NOT ready: engine context snapshot bound (15b7037c76790e99e60c703713800622d70ae55b); canonical detector cooldown key implemented; bounded retained-event identity deduplication, mapped-loopback rejection and DNS-volume family grouping implemented; verify cooldown suppression, selector/telemetry path and confidence, authored future/expired snapshot and mutated-source detector negatives; authored exact producer-window boundary and mapped-IP detector positive; authored two-emitted-family detector negative and same-instance canonical alias cooldown negative; authored detector confidence-floor assertion and pre-DNS snapshot immutability regression; authored full engine selection/alert emission and repeat suppression assertions; verify emitted-event fixture and detector cooldown boundaries; stop DNS fixture at first R031 emission to avoid consuming R272 cooldown before probe (source d872c04bfb0d304f7dc803420121bfe4d2c6b716); repeated real FTP packet evaluation after two emitted families asserts one retained R014 and no R272 match (source 69fa21346b675ca8946630ffca5f6de65f73b8a5); direct retained-event identity replay fixture authored (actual R014 event, private production ingestion); monotonic retention watermark and replay reset implemented; ordering regression authored against actual R014/R026 emitted identities: stale rejection, inclusive boundary, two-family detector negative and watermark reset (base cc3a0f8bd759b6260abfd7e70aaca8406fe015ab); static compatibility still pending; isolated exact-identity retention fixture from legitimate later FTP emissions (base 5da6461f285c252408678e0916205b00535f1fab); replay clock lower-bound cutoff clamped in producer and snapshot; actual emitted identity fixture covers early clock, future exclusion and inclusive expiry (base 4bfb0f9972a697dfe92090adac0d24d1ae8b42d0); duplicate future replay cannot advance watermark or evict another real emitted family (base 47e9e4153a4d3448b0f7df5074a4aeada6da22ae); static review at 4f80b7cfd2e665ab62b7c4d55453aeadf419870e: EvasionInfra MatchEvasionInfra returns Match with suppressed event, not NoMatch; shared cooldown survives new detector instances; corrected canonical and mapped alias assertions to require matched suppressed events; engine context source binding and post-policy ingestion inspected; selector defect confirmed at 80becb2edee6d3994d948c0aca49bac8747ab425: numeric TLS range incorrectly included R272; narrowed range to R271, added explicit default selector and telemetry assertions to existing full-engine positive fixture; source candidate, unexecuted; static telemetry/catalog review at b0d3316890fd317cdd28af26d092fffc95204bdb: validator requires every declared kind and intelligence requirement; removed unrelated Process and generic text requirement for R272 only, retained Flow/source/destination/protocol and trusted snapshot gate; full-engine positive probe now lacks process and text; authored/unexecuted; runtime policy review at 550eef67175deca398a8f22741f35a501a0e4d17: PrepareDetectionEvent resets rule-owned Suppressed to None; preserve R272 suppression through tuning/noise/suppression policy before journal and emission; existing full-engine repeat negative exercises this path; source candidate, unexecuted; independent bounded event identity retention (16384, fail closed at capacity), replay reset and actual replacement-emission replay regression authored at base 8910c70ae468182535cfe8bd8b139664fbbee92f; unexecuted; timestamp-priority expiry queue replaces full identity scan, reset clears both indexes, delayed-arrival expiry and retained/expired identity regression authored at base a3d8b44e1ec5ea8f43e28092e78a5dc8ba971e63; unexecuted; capacity exhaustion at inclusive boundary, detector negative, one-tick expiry recovery and index reset regression authored at base 81fed840e47a75563a85cea0ef8ff2d04fcc1c23 (identity-only fixture, actual R014 admission); unexecuted; non-unicast source admission hardened at base 2f57971c0a9b3a30073a12c37ca728e49f108a2f: IPv4 limited broadcast, IPv4 multicast (including mapped alias), IPv6 multicast rejected before identity retention; actual emitted R014 identity regression verifies rejection and later valid admission; authored/unexecuted; producer rejects non-None suppression dispositions independently of caller; actual R014 identity suppressed/shadowed rejection and subsequent admission regression authored at base 4cb88b123fd31bec166ebc5b882ecc726f4ff07e; unexecuted |
| R273 | Carthago/Engine/Rules/Expansion/R273_ImpossibleTravelAuthenticationSequenceRule.cs | trusted account-linked successful IdP sign-ins, timestamps and independent geolocation | unavailable: detector unconditionally returns NoMatch | pending | pending | producer-blocked at 5da6461f285c252408678e0916205b00535f1fab; verified fail-closed detector; inspect existing TrustedAudit adapters before implementing |
| R274 | Carthago/Engine/Rules/Expansion/R274_MFAPushFatiguePatternRule.cs | trusted distinct MFA prompt IDs, account, delivery and denial/approval outcomes | unavailable: detector unconditionally returns NoMatch | pending | pending | producer-blocked at 5da6461f285c252408678e0916205b00535f1fab; verified fail-closed detector; inspect existing TrustedAudit adapters before implementing |
| R276 | Carthago/Engine/Rules/Expansion/R276_OAuthConsentGrantAbuseIndicatorRule.cs | Carthago.Tests/R276R278FailClosedEvidenceTests.cs (negative-only, authored/unexecuted) | Carthago.Tests/R276R278FailClosedEvidenceTests.cs (spoofed labels/benign near miss, authored/unexecuted) | missing source and contradictory context, authored/unexecuted | producer-blocked; inspected at 480d62e2320ca93983dd6d4cbd4b22a2107be621; signed IdP consent grant audit with tenant/app/actor/scopes/outcome; URL/scope strings are not grant evidence; no verified producer and no detector-positive test; NOT ready | audit pending |
| R277 | Carthago/Engine/Rules/Expansion/R277_LegacyProtocolAuthenticationAttemptRule.cs | Carthago.Tests/R276R278FailClosedEvidenceTests.cs (negative-only, authored/unexecuted) | Carthago.Tests/R276R278FailClosedEvidenceTests.cs (spoofed labels/benign near miss, authored/unexecuted) | missing source and contradictory context, authored/unexecuted | producer-blocked; inspected at 480d62e2320ca93983dd6d4cbd4b22a2107be621; parser-attributed AUTH command or trusted server audit with attempt identity/outcome; mail ports and banners alone are insufficient; no verified producer and no detector-positive test; NOT ready | audit pending |
| R278 | Carthago/Engine/Rules/Expansion/R278_PasswordSprayLowAndSlowAcrossAccountsRule.cs | Carthago.Tests/R276R278FailClosedEvidenceTests.cs (negative-only, authored/unexecuted) | Carthago.Tests/R276R278FailClosedEvidenceTests.cs (spoofed labels/benign near miss, authored/unexecuted) | missing source and contradictory context, authored/unexecuted | producer-blocked; inspected at 480d62e2320ca93983dd6d4cbd4b22a2107be621; trusted failed-auth outcomes with stable account/source/timestamps; request counts do not establish account spray; no verified producer and no detector-positive test; NOT ready | audit pending |
| R279 | Carthago/Engine/Rules/Expansion/R279_CredentialStuffingRotatingUserAgentRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R280 | Carthago/Engine/Rules/Expansion/R280_SessionTokenReplayAcrossGeographiesRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R281 | Carthago/Engine/Rules/Expansion/R281_SuspiciousAdminConsoleLoginToCloudRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R282 | Carthago/Engine/Rules/Expansion/R282_VPNLoginFollowedByInternalScanRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R283 | Carthago/Engine/Rules/Expansion/R283_SAMLRelayStateInjectionPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R284 | Carthago/Engine/Rules/Expansion/R284_OIDCAuthorizationCodeLeakageInURLRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R285 | Carthago/Engine/Rules/Expansion/R285_SCIMBulkUserEnumerationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R287 | Carthago/Engine/Rules/Expansion/R287_KerberosPreauthFailureDistributedSprayRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R288 | Carthago/Engine/Rules/Expansion/R288_NTLMv1AuthenticationObservedRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R289 | Carthago/Engine/Rules/Expansion/R289_RADIUSAuthenticationFailureBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R290 | Carthago/Engine/Rules/Expansion/R290_CitrixGatewayExploitProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R291 | Carthago/Engine/Rules/Expansion/R291_FortinetSSLVPNExploitProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R292 | Carthago/Engine/Rules/Expansion/R292_PaloAltoGlobalProtectExploitProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R293 | Carthago/Engine/Rules/Expansion/R293_KubernetesAnonymousAPIDiscoveryProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R294 | Carthago/Engine/Rules/Expansion/R294_KubernetesSecretsAPIAccessProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R295 | Carthago/Engine/Rules/Expansion/R295_KubernetesExecIntoPodOverAPIRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R296 | Carthago/Engine/Rules/Expansion/R296_KubernetesPortForwardAbuseIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R297 | Carthago/Engine/Rules/Expansion/R297_KubernetesServiceAccountTokenExfilRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R298 | Carthago/Engine/Rules/Expansion/R298_ContainerRuntimeSocketExposureProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R299 | Carthago/Engine/Rules/Expansion/R299_DockerRemoteAPIContainerCreateRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R300 | Carthago/Engine/Rules/Expansion/R300_KubernetesEtcdClientAccessExternalRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R301 | Carthago/Engine/Rules/Expansion/R301_KubeletReadonlyPortProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R302 | Carthago/Engine/Rules/Expansion/R302_KubeletRunOrExecProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R303 | Carthago/Engine/Rules/Expansion/R303_ContainerRegistryManifestEnumerationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R304 | Carthago/Engine/Rules/Expansion/R304_ContainerRegistryAnonymousPullBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R305 | Carthago/Engine/Rules/Expansion/R305_ImageRegistryPushFromWorkstationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R306 | Carthago/Engine/Rules/Expansion/R306_DockerBuildContextArchiveUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R307 | Carthago/Engine/Rules/Expansion/R307_KubernetesDashboardExposureProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R308 | Carthago/Engine/Rules/Expansion/R308_HelmTillerLegacyPortExposureRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R309 | Carthago/Engine/Rules/Expansion/R309_IstioEnvoyAdminEndpointProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R310 | Carthago/Engine/Rules/Expansion/R310_ServiceMeshSidecarBypassPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R311 | Carthago/Engine/Rules/Expansion/R311_CloudWorkloadMetadataTokenRequestRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R312 | Carthago/Engine/Rules/Expansion/R312_KubernetesNetworkPolicyBypassIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R313 | Carthago/Engine/Rules/Expansion/R313_DirectSMTPToMXFromWorkstationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R314 | Carthago/Engine/Rules/Expansion/R314_SMTPAuthenticationFailureBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R315 | Carthago/Engine/Rules/Expansion/R315_IMAPLoginFailureSprayRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R316 | Carthago/Engine/Rules/Expansion/R316_POP3CleartextCredentialExposureRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R317 | Carthago/Engine/Rules/Expansion/R317_ExchangeAutodiscoverExternalSprayRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R318 | Carthago/Engine/Rules/Expansion/R318_EWSEnumerationBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R319 | Carthago/Engine/Rules/Expansion/R319_OWAAdminOrECPProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R320 | Carthago/Engine/Rules/Expansion/R320_M365GraphMailExportPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R321 | Carthago/Engine/Rules/Expansion/R321_GmailAPIBulkMessageReadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R322 | Carthago/Engine/Rules/Expansion/R322_MailForwardingRuleCreationIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R323 | Carthago/Engine/Rules/Expansion/R323_SuspiciousAttachmentDownloadBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R324 | Carthago/Engine/Rules/Expansion/R324_PhishingKitURIPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R325 | Carthago/Engine/Rules/Expansion/R325_LookalikeSenderDomainContactRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R326 | Carthago/Engine/Rules/Expansion/R326_DMARCSPFDKIMReconQueryBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R327 | Carthago/Engine/Rules/Expansion/R327_SlackOAuthAppInstallCallbackRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R328 | Carthago/Engine/Rules/Expansion/R328_TeamsWebhookAbuseIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R329 | Carthago/Engine/Rules/Expansion/R329_SharePointBulkDownloadPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R330 | Carthago/Engine/Rules/Expansion/R330_OneDriveAnonymousShareLinkMassAccessRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R331 | Carthago/Engine/Rules/Expansion/R331_CalendarInvitePhishingLinkPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R332 | Carthago/Engine/Rules/Expansion/R332_EmailArchiveExportDownloadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R333 | Carthago/Engine/Rules/Expansion/R333_SMBNullSessionEnumerationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R334 | Carthago/Engine/Rules/Expansion/R334_SMBNamedPipeEnumerationBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R335 | Carthago/Engine/Rules/Expansion/R335_LSARPCSAMREnumerationPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R336 | Carthago/Engine/Rules/Expansion/R336_DRSUAPIReplicationAttemptRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R337 | Carthago/Engine/Rules/Expansion/R337_KerberosS4UDelegationAbuseIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R338 | Carthago/Engine/Rules/Expansion/R338_KerberosRC4DowngradeIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R339 | Carthago/Engine/Rules/Expansion/R339_SMBSigningDisabledSensitiveHostRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R340 | Carthago/Engine/Rules/Expansion/R340_RemoteRegistryServiceAccessRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R341 | Carthago/Engine/Rules/Expansion/R341_ScheduledTaskRemoteCreationPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R342 | Carthago/Engine/Rules/Expansion/R342_WindowsAdminCenterExposureProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R343 | Carthago/Engine/Rules/Expansion/R343_PowerShellRemotingEncodedCommandRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R344 | Carthago/Engine/Rules/Expansion/R344_WMIEventSubscriptionRemotePatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R345 | Carthago/Engine/Rules/Expansion/R345_DCOMMMC20LateralIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R346 | Carthago/Engine/Rules/Expansion/R346_MSSQLXpCmdshellUseIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R347 | Carthago/Engine/Rules/Expansion/R347_MSSQLLinkedServerEnumerationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R348 | Carthago/Engine/Rules/Expansion/R348_LDAPAdminSDHolderReconRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R349 | Carthago/Engine/Rules/Expansion/R349_LDAPKerberoastSPNEnumerationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R350 | Carthago/Engine/Rules/Expansion/R350_LDAPPasswordPolicyReconRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R361 | Carthago/Engine/Rules/Expansion/R361_GitHubActionsOIDCTokenRequestRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R371 | Carthago/Engine/Rules/Expansion/R371_MavenRepositoryCredentialUseRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R372 | Carthago/Engine/Rules/Expansion/R372_DependencyConfusionPackageNamePatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R373 | Carthago/Engine/Rules/Expansion/R373_AWSSTSAssumeRoleBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R374 | Carthago/Engine/Rules/Expansion/R374_AWSIAMAccessKeyInURLRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R376 | Carthago/Engine/Rules/Expansion/R376_AWSS3GetObjectBulkDownloadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R377 | Carthago/Engine/Rules/Expansion/R377_AWSEC2UserDataMetadataProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R379 | Carthago/Engine/Rules/Expansion/R379_AWSCloudTrailStopLoggingIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R380 | Carthago/Engine/Rules/Expansion/R380_AWSGuardDutyFindingExfilIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R381 | Carthago/Engine/Rules/Expansion/R381_AzureARMTokenRequestBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R383 | Carthago/Engine/Rules/Expansion/R383_AzureStorageSASTokenInURLRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R384 | Carthago/Engine/Rules/Expansion/R384_AzureIMDSTokenRequestRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R385 | Carthago/Engine/Rules/Expansion/R385_GCPOAuthScopeBroadRequestRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R386 | Carthago/Engine/Rules/Expansion/R386_GCPStorageSignedURLMassAccessRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R387 | Carthago/Engine/Rules/Expansion/R387_GCPServiceAccountKeyDownloadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R389 | Carthago/Engine/Rules/Expansion/R389_NgrokTunnelCreationOrAuthRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R390 | Carthago/Engine/Rules/Expansion/R390_TailscaleTailnetAuthIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R391 | Carthago/Engine/Rules/Expansion/R391_ZeroTierNetworkJoinIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R392 | Carthago/Engine/Rules/Expansion/R392_PublicCloudCLIUserAgentFromServerRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R393 | Carthago/Engine/Rules/Expansion/R393_CobaltStrikeBeaconURIPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R394 | Carthago/Engine/Rules/Expansion/R394_CobaltStrikeMalleableC2HeaderPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R395 | Carthago/Engine/Rules/Expansion/R395_SliverC2MTLSPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R396 | Carthago/Engine/Rules/Expansion/R396_MythicAgentCallbackPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R397 | Carthago/Engine/Rules/Expansion/R397_MetasploitMeterpreterStagerPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R398 | Carthago/Engine/Rules/Expansion/R398_HavocC2CallbackPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R399 | Carthago/Engine/Rules/Expansion/R399_BruteRatelBadgerPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R400 | Carthago/Engine/Rules/Expansion/R400_CovenantGruntCallbackPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R401 | Carthago/Engine/Rules/Expansion/R401_EmpireStagerURIPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R402 | Carthago/Engine/Rules/Expansion/R402_AsyncRATTelegramC2PatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R403 | Carthago/Engine/Rules/Expansion/R403_RemcosRATC2PatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R404 | Carthago/Engine/Rules/Expansion/R404_AgentTeslaSMTPExfilPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R405 | Carthago/Engine/Rules/Expansion/R405_QakBotURIPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R406 | Carthago/Engine/Rules/Expansion/R406_EmotetLoaderURIPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R407 | Carthago/Engine/Rules/Expansion/R407_BumblebeeLoaderURIPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R408 | Carthago/Engine/Rules/Expansion/R408_SocGholishFakeUpdatePatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R409 | Carthago/Engine/Rules/Expansion/R409_RaspberryRobinShortLNKPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R410 | Carthago/Engine/Rules/Expansion/R410_RedlineStealerExfilPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R411 | Carthago/Engine/Rules/Expansion/R411_LummaStealerGatePatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R412 | Carthago/Engine/Rules/Expansion/R412_GenericBeaconJitterLowVarianceRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R413 | Carthago/Engine/Rules/Expansion/R413_CitrixNetscalerGatewayScanPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R414 | Carthago/Engine/Rules/Expansion/R414_IvantiConnectSecureExploitProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R415 | Carthago/Engine/Rules/Expansion/R415_F5BIGIPTMUIProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R416 | Carthago/Engine/Rules/Expansion/R416_SonicWallSSLVPNExploitProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R417 | Carthago/Engine/Rules/Expansion/R417_CiscoASAWebVPNProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R418 | Carthago/Engine/Rules/Expansion/R418_MikroTikWinboxExternalAccessRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R419 | Carthago/Engine/Rules/Expansion/R419_UbiquitiDiscoveryExternalExposureRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R420 | Carthago/Engine/Rules/Expansion/R420_QNAPQTSAdminProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R421 | Carthago/Engine/Rules/Expansion/R421_SynologyDSMAdminProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R422 | Carthago/Engine/Rules/Expansion/R422_VMwareVCenterSOAPProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R423 | Carthago/Engine/Rules/Expansion/R423_VMwareESXiHostdProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R424 | Carthago/Engine/Rules/Expansion/R424_ProxmoxAPIExposureProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R425 | Carthago/Engine/Rules/Expansion/R425_ApacheSolrAdminProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R426 | Carthago/Engine/Rules/Expansion/R426_ElasticsearchClusterInfoExternalRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R427 | Carthago/Engine/Rules/Expansion/R427_KibanaConsoleExposureRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R428 | Carthago/Engine/Rules/Expansion/R428_GrafanaAdminLoginProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R429 | Carthago/Engine/Rules/Expansion/R429_PrometheusMetricsExposureExternalRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R430 | Carthago/Engine/Rules/Expansion/R430_JupyterNotebookTokenProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R431 | Carthago/Engine/Rules/Expansion/R431_AirflowAdminEndpointProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R432 | Carthago/Engine/Rules/Expansion/R432_ConsulNomadAdminProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R433 | Carthago/Engine/Rules/Expansion/R433_PostgreSQLExternalLoginAttemptRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R434 | Carthago/Engine/Rules/Expansion/R434_MySQLExternalLoginAttemptRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R435 | Carthago/Engine/Rules/Expansion/R435_MSSQLExternalLoginAttemptRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R436 | Carthago/Engine/Rules/Expansion/R436_MongoDBExternalExposureProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R437 | Carthago/Engine/Rules/Expansion/R437_RedisCONFIGSETIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R438 | Carthago/Engine/Rules/Expansion/R438_RedisReplicationAbuseIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R439 | Carthago/Engine/Rules/Expansion/R439_MemcachedStatsEnumerationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R440 | Carthago/Engine/Rules/Expansion/R440_ElasticsearchSnapshotRepositoryProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R441 | Carthago/Engine/Rules/Expansion/R441_CassandraCQLExternalProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R442 | Carthago/Engine/Rules/Expansion/R442_OracleTNSEnumerationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R443 | Carthago/Engine/Rules/Expansion/R443_CouchDBAdminProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R444 | Carthago/Engine/Rules/Expansion/R444_InfluxDBQueryEndpointExposureRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R445 | Carthago/Engine/Rules/Expansion/R445_ClickHouseHTTPSQLProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R446 | Carthago/Engine/Rules/Expansion/R446_Neo4jBrowserExposureProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R447 | Carthago/Engine/Rules/Expansion/R447_RabbitMQManagementProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R448 | Carthago/Engine/Rules/Expansion/R448_KafkaBrokerExternalAccessRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R449 | Carthago/Engine/Rules/Expansion/R449_ZookeeperFourLetterWordProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R450 | Carthago/Engine/Rules/Expansion/R450_NATSBrokerExternalAccessRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R451 | Carthago/Engine/Rules/Expansion/R451_MQTTAnonymousLoginPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R452 | Carthago/Engine/Rules/Expansion/R452_DatabaseLargeResultExportPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R453 | Carthago/Engine/Rules/Expansion/R453_MDNSServiceEnumerationHighRateRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R454 | Carthago/Engine/Rules/Expansion/R454_SSDPMSEARCHExternalAnswerRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R455 | Carthago/Engine/Rules/Expansion/R455_AirPlayDiscoveryFromNonMediaHostRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R456 | Carthago/Engine/Rules/Expansion/R456_ChromecastDiscoveryBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R457 | Carthago/Engine/Rules/Expansion/R457_PrinterJetDirectExternalAccessRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R458 | Carthago/Engine/Rules/Expansion/R458_IPPPrintingFromExternalHostRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R459 | Carthago/Engine/Rules/Expansion/R459_SMBBrowseElectionAnomalyRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R460 | Carthago/Engine/Rules/Expansion/R460_NetBIOSNameQuerySweepRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R461 | Carthago/Engine/Rules/Expansion/R461_DHCPStarvationCandidateRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R462 | Carthago/Engine/Rules/Expansion/R462_DHCPRogueOfferDetectedRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R463 | Carthago/Engine/Rules/Expansion/R463_ARPGratuitousStormRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R464 | Carthago/Engine/Rules/Expansion/R464_ARPDuplicateMACFlipFlopRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R465 | Carthago/Engine/Rules/Expansion/R465_IPv6SLAACPrefixChangeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R466 | Carthago/Engine/Rules/Expansion/R466_WiFiControllerAdminProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R467 | Carthago/Engine/Rules/Expansion/R467_CAPWAPExternalControllerAttemptRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R468 | Carthago/Engine/Rules/Expansion/R468_BluetoothGatewayInternetEgressRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R469 | Carthago/Engine/Rules/Expansion/R469_AndroidDebugBridgeNetworkAccessRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R470 | Carthago/Engine/Rules/Expansion/R470_MobileMDMEnrollmentBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R471 | Carthago/Engine/Rules/Expansion/R471_RDPClipboardFileTransferIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R472 | Carthago/Engine/Rules/Expansion/R472_RemoteSupportToolUnexpectedUseRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R473 | Carthago/Engine/Rules/Expansion/R473_ModbusFunction43DeviceIdEnumerationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R474 | Carthago/Engine/Rules/Expansion/R474_ModbusForceListenOnlyModeAttemptRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R475 | Carthago/Engine/Rules/Expansion/R475_ModbusDiagnosticsFunctionAbuseRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R476 | Carthago/Engine/Rules/Expansion/R476_ModbusCoilWriteBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R477 | Carthago/Engine/Rules/Expansion/R477_S7StartStopCPUCommandIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R478 | Carthago/Engine/Rules/Expansion/R478_S7UploadDownloadBlockTransferRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R479 | Carthago/Engine/Rules/Expansion/R479_S7PLCIdentificationProbeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R480 | Carthago/Engine/Rules/Expansion/R480_DNP3ControlRelayOutputBlockRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R481 | Carthago/Engine/Rules/Expansion/R481_DNP3FreezeCounterCommandRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R482 | Carthago/Engine/Rules/Expansion/R482_IEC104ControlCommandExternalRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R483 | Carthago/Engine/Rules/Expansion/R483_OPCUABrowseNodeBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R484 | Carthago/Engine/Rules/Expansion/R484_OPCUAWriteRequestIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R487 | Carthago/Engine/Rules/Expansion/R487_ProfinetDCPSetNameRequestRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R488 | Carthago/Engine/Rules/Expansion/R488_EtherNetIPListIdentityBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R489 | Carthago/Engine/Rules/Expansion/R489_EtherNetIPForwardOpenExternalRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R490 | Carthago/Engine/Rules/Expansion/R490_IEC61850MMSWriteIndicatorRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R491 | Carthago/Engine/Rules/Expansion/R491_GOOSEMulticastOutsideSubstationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R492 | Carthago/Engine/Rules/Expansion/R492_HistorianBulkQueryFromWorkstationRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R493 | Carthago/Engine/Rules/Expansion/R493_BrowserPasswordStoreFileUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R494 | Carthago/Engine/Rules/Expansion/R494_SSHPrivateKeyUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R495 | Carthago/Engine/Rules/Expansion/R495_KeePassDatabaseUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R496 | Carthago/Engine/Rules/Expansion/R496_VPNConfigFileUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R497 | Carthago/Engine/Rules/Expansion/R497_BrowserCookieDatabaseUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R498 | Carthago/Engine/Rules/Expansion/R498_LargeClipboardSyncUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R499 | Carthago/Engine/Rules/Expansion/R499_RemoteDesktopFileTransferBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R500 | Carthago/Engine/Rules/Expansion/R500_CompressedArchiveThenCloudUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R501 | Carthago/Engine/Rules/Expansion/R501_MultipartFormDataHighEntropyFilenameRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R502 | Carthago/Engine/Rules/Expansion/R502_DataURIBase64POSTLargeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R503 | Carthago/Engine/Rules/Expansion/R503_PastebinRawPOSTBulkRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R504 | Carthago/Engine/Rules/Expansion/R504_GitHubGistSecretPostRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R505 | Carthago/Engine/Rules/Expansion/R505_DiscordAttachmentUploadBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R506 | Carthago/Engine/Rules/Expansion/R506_TelegramDocumentExfilBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R507 | Carthago/Engine/Rules/Expansion/R507_MegaNZUploadPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R508 | Carthago/Engine/Rules/Expansion/R508_RcloneUserAgentEgressRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R509 | Carthago/Engine/Rules/Expansion/R509_RsyncExternalPushRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R510 | Carthago/Engine/Rules/Expansion/R510_S3CompatibleUnknownEndpointUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R511 | Carthago/Engine/Rules/Expansion/R511_DBClientExportThenHTTPUploadRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R512 | Carthago/Engine/Rules/Expansion/R512_SensitiveFilenameToPersonalEmailRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R513 | Carthago/Engine/Rules/Expansion/R513_SSHDynamicSOCKSProxyUseRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R514 | Carthago/Engine/Rules/Expansion/R514_ChiselTunnelHandshakeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R515 | Carthago/Engine/Rules/Expansion/R515_FRPTunnelHandshakeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R516 | Carthago/Engine/Rules/Expansion/R516_CloudflaredTunnelHandshakeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R517 | Carthago/Engine/Rules/Expansion/R517_NgrokTunnelHandshakeV2Rule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R518 | Carthago/Engine/Rules/Expansion/R518_ReverseSSHTunnelPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R519 | Carthago/Engine/Rules/Expansion/R519_DNSOverQUICUnapprovedResolverRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R520 | Carthago/Engine/Rules/Expansion/R520_MASQUECONNECTUDPProxyUseRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R521 | Carthago/Engine/Rules/Expansion/R521_HTTPCONNECTToNonProxyPortRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R522 | Carthago/Engine/Rules/Expansion/R522_WebSocketTunnelToIPLiteralRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R523 | Carthago/Engine/Rules/Expansion/R523_DomainFrontingHostSNIMismatchRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R524 | Carthago/Engine/Rules/Expansion/R524_ECHToUnapprovedProviderRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R525 | Carthago/Engine/Rules/Expansion/R525_QUICConnectionIDRotationBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R526 | Carthago/Engine/Rules/Expansion/R526_PacketSizeMimicryBeaconRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R527 | Carthago/Engine/Rules/Expansion/R527_SleepyBeaconLongGapPatternRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R528 | Carthago/Engine/Rules/Expansion/R528_UserAgentRandomizationBurstRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R529 | Carthago/Engine/Rules/Expansion/R529_SensorHeartbeatMissingForSiteRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R530 | Carthago/Engine/Rules/Expansion/R530_SensorClockSkewIncreasingRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R531 | Carthago/Engine/Rules/Expansion/R531_DetectionJournalDiskSpaceLowRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R532 | Carthago/Engine/Rules/Expansion/R532_OutboxRetryStormRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R533 | Carthago/Engine/Rules/Expansion/R533_RuleMatchVolumeAnomalyRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R534 | Carthago/Engine/Rules/Expansion/R534_RuleSilentUnexpectedlyRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R535 | Carthago/Engine/Rules/Expansion/R535_TelemetryFieldCoverageDropRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R536 | Carthago/Engine/Rules/Expansion/R536_ParserErrorSpikeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R537 | Carthago/Engine/Rules/Expansion/R537_GeoIPLookupFailureSpikeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R538 | Carthago/Engine/Rules/Expansion/R538_ReputationLookupFailureSpikeRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R539 | Carthago/Engine/Rules/Expansion/R539_BaselineStoreWriteFailureRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R540 | Carthago/Engine/Rules/Expansion/R540_FeedbackStoreWriteFailureRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R541 | Carthago/Engine/Rules/Expansion/R541_ContentPackValidationFailureRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R542 | Carthago/Engine/Rules/Expansion/R542_ReplayBenchmarkRegressionRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R543 | Carthago/Engine/Rules/Expansion/R543_RuleConfigProfileDriftRule.cs | pending inspection | pending inspection | pending | pending | audit pending |
| R544 | Carthago/Engine/Rules/Expansion/R544_ExcessiveSuppressionRatioRule.cs | pending inspection | pending inspection | pending | pending | audit pending |

## Resume checkpoint

R271 source inspected: calls ThreatFeedService.TryMatch on exact observed source and NetworkBatch271275Evidence.HasSourceOverlap with snapshot LastBuild and evaluation timestamp. Profile floor 88, Alert, 45-minute cooldown. Historical progress explicitly calls helper positive contract-only; inspect actual service snapshot lifecycle and reputation population before adding detector tests. R270 and R272–R274 historical fail-closed dispositions require trusted pipeline, emitted-rule correlation and IdP/MFA producers respectively; no new qualification claim. Next: inspect these five implementations and existing test paths, prioritize R271 real feed snapshot integration. Do not use a fake global feed or weaken policy. No source or test modifications in this checkpoint.

### R271 checkpoint — snapshot statistics consistency

Inspected source `a94633003ba3de24ab53a07dace8e42eaaf7c721`. `ThreatFeedService.CurrentStats` now captures one snapshot before reading all counters and freshness; no detector threshold or qualification status changed. The configured URLHaus adapter currently emits host/domain/URL indicators, not explicit IPv4 indicators; exact IP classification in lookup alone does not establish an independent reputation producer. Next: inspect reputation producer and add real feed-to-detector positive/negative fixtures; keep R271 pending. No tests executed.


## Portable R601 checkpoint — 1d810357c0f7e64ff6956dfab4329155ce2c8a85

Parser prerequisite authored/unexecuted: Carthago.Core/PortableApplicationParsers.cs exposes CompleteRequestHeaders only for terminated HTTP/1.x request blocks within 8192 bytes with valid header names and no invalid control bytes. Carthago.Cli.Tests/PortableApplicationParserTests.cs covers complete, truncated, malformed, folded, empty-value and oversized headers. Existing parser flags unchanged. This is parser evidence only, not detector qualification. Next: bind completeness and header presence to captured record in PortablePacketProcessor, share R601 predicate with Windows, add raw replay and parity tests, register only after integration. Portable catalog remains 19; R601 not ready.

## Portable R601 capture evidence checkpoint — 865cfcf6a784de36a3142600dfe5b2b011de864a

Bound complete request headers and case-insensitive User-Agent/Referer name presence to the shared raw-frame processor on complete SYN-anchored first client payloads; clear on TLS classification. Internal setters prevent default JSON restoration. Four raw capture cases authored in Carthago.Tests/R601HeaderCaptureTests.cs (complete absent, empty present, truncated, malformed), zero executed. This is producer evidence only; shared predicate, record-binding review, detector replay/parity and registration remain. Portable count 19. R272 final runtime-policy review and R273–R274 trusted authentication remain open.

## R601 shared detector checkpoint — df80e065c227d46b2800004e803b95860033a3ad

Implemented Core PortableR601Detector and Windows delegation to the same request-only predicate/cooldown. Requires complete capture-derived headers and rejects present (including empty) User-Agent or Referer, preserving prior query signatures, Shadow policy and confidence floor. Six raw capture-to-Core/Windows parity cases authored; grouped R596–R605 R601 fixtures now use actual capture producer rather than fabricated header absence. Zero tests executed. Catalog registration remains pending review of replay/CLI capability contracts and record mutation binding; portable count remains 19. R272 final policy gate and R273–R274 producer work remain open.


## R601 record binding checkpoint — b172db719bd170a9b54025c8bc0ac7ccb279bc2f

Capture producer now binds complete-header evidence to the exact record ID, endpoints, ports, method, URI, header summary, agent and host. Shared detector rejects changed metadata even when capture flags remain true. Six raw-capture mutation cases authored against Core and Windows, zero executed. No new registration or readiness promotion; next inspect CLI catalog and replay registration. R272 policy review and R273–R274 trusted producer remain open.

## R601 portable registration checkpoint — 935f9fbb27f4af8ea7ca07cad7a76b7e226f9dd8

Register the existing capture-bound shared evaluator in PortableRuleCatalog (20 compiled IDs, 980 outside catalog); declare complete header and presence evidence. Update capability tests and existing unanchored replay control; add six actual classic PCAP replay cases with SYN/SYN-ACK and complete, empty-header, incomplete, benign and wrong-method controls. Windows Shadow policy unchanged; replay does not evaluate Windows policy. Authored six cases, executed zero; source candidate, not a passing qualification or field accuracy claim. Next: verify replay state/reset and pcapng parity, reconcile CLI documentation and R272 policy gate; then R606–R610. R270/R273–R274 remain producer work.


## 2026-11-15 — R601 portable capture-format and invocation isolation

Base `214a6752765e8bfed1c79aa9f051884e811f4a1c`. Extend `Carthago.Cli.Tests/PortableReplayTests.cs` R601ReplayRequiresCompleteAnchoredRequest: all six existing raw-frame positive/negative cases now run in classic PCAP and PCAPNG, twice each with fresh CLI invocations. Expected identical match counts and no query leakage; 24 replay invocations authored, zero executed. No policy or predicate change. R601 remains source candidate; same-capture cooldown/reset and documentation reconciliation pending. Next: R272 runtime policy and R606–R610 portable migration. Catalog remains 20 registered / 980 remaining at last registration checkpoint.


## 2026-11-15 — R601 cooldown and capture epochs

Base `dc97a873a4eb423b31126dc4ecce2a607f955302`. Added raw PCAP same-source/destination fresh-flow requests at 599 and 600 seconds after first match (expected suppressed then match), and PCAPNG independent interface/section handshakes (three expected matches). Reused existing raw segment fixture with distinct client ports. One new test authored, zero executed; no predicate or policy changes. R601 remains source candidate pending static CLI documentation reconciliation and owner tests. Next R272 policy review and R606–R610 migration. Portable registration last established 20/1000.


## 2026-11-16 — 1,000-rule registry reconciliation

Current source snapshot `c54b87b4b6c6a7d82e64d7226f7c5899778d9313`: 1,000 canonical unique registered core IDs R001–R1000, no duplicates or gaps, exactly one implementation path each. Master catalog refreshed to 1,000; all 35 new rules have dedicated quality-test files, not execution proof. Current Windows exact-ID inventory: 27 records (17 historical-pass, 4 authored-unexecuted, 6 missing); 973 IDs not yet represented. Reviewed historical pass manifest: 17, original artifacts not admitted. Portable R586–R605: 40 distinct positive and 40 distinct negative replay cases, each executed on Windows and WSL2 at dc43933775cb95a4685ecc860f93fa60b2ad3d1a (80 positive + 80 negative executions, all expected outcomes). No new executions or promotion; full 1,000-rule positive/negative Windows totals remain unknown until exact artifact mapping. R601 portable milestone already reached; no additional portable IDs inferred. Next: artifact-backed case mapping and exact-ID admission; preserve R272/producer backlog and current-SHA execution authorization.


## 2026-11-16 R276–R278 audit increment

Source inspected at 480d62e2320ca93983dd6d4cbd4b22a2107be621. All three detectors unconditionally return InsufficientEvidence/NoMatch. Added negative-only fail-closed regression cases in `Carthago.Tests/R276R278FailClosedEvidenceTests.cs` for spoofed high-risk text, benign protocol near miss, and missing identity/source. These do **not** count as detector-positive qualification. Producer dependencies remain explicit in each row; next inspect R279 and existing trusted authentication adapters, then move to an independently actionable producer if still blocked. Authored only: no compilation, Windows test or native capture executed. Historical 717/248/35 evidence preserved.
