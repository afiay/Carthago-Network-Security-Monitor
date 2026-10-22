# R273-R544 Selected Detection Rule Expansion

This expansion adds 272 curated telemetry-driven rules, raising Carthago from 272 to 544 rules while preserving every previous rule ID. Rules are concrete descriptors backed by `ExtendedRuleDetectors` specifications. They emit only when observable `TrafficRecord` evidence exists and otherwise return `NoMatch`.

The selection focuses on modern SIEM/NDR/SOAR coverage gaps: identity abuse, Kubernetes/container security, collaboration and email exfiltration, Windows/AD lateral movement, DevOps and cloud control-plane abuse, malware/C2 frameworks, network appliance exposure, database/cache exposures, local discovery, OT/ICS operations, data-loss staging, evasion/tunneling, and platform health.

| Rule | Name | Category | Severity |
|---|---|---|---|
| R273 | Impossible Travel Authentication Sequence | IdentityAdvanced | High |
| R274 | MFA Push Fatigue Pattern | IdentityAdvanced | High |
| R275 | OAuth Device Code Phishing Indicator | IdentityAdvanced | High |
| R276 | OAuth Consent Grant Abuse Indicator | IdentityAdvanced | High |
| R277 | Legacy Protocol Authentication Attempt | IdentityAdvanced | Medium |
| R278 | Password Spray Low And Slow Across Accounts | IdentityAdvanced | High |
| R279 | Credential Stuffing Rotating User Agent | IdentityAdvanced | High |
| R280 | Session Token Replay Across Geographies | IdentityAdvanced | High |
| R281 | Suspicious Admin Console Login To Cloud | IdentityAdvanced | High |
| R282 | VPN Login Followed By Internal Scan | IdentityAdvanced | Critical |
| R283 | SAML RelayState Injection Pattern | IdentityAdvanced | High |
| R284 | OIDC Authorization Code Leakage In URL | IdentityAdvanced | High |
| R285 | SCIM Bulk User Enumeration | IdentityAdvanced | Medium |
| R286 | LDAP Simple Bind Over Cleartext External | IdentityAdvanced | High |
| R287 | Kerberos Preauth Failure Distributed Spray | IdentityAdvanced | High |
| R288 | NTLMv1 Authentication Observed | IdentityAdvanced | High |
| R289 | RADIUS Authentication Failure Burst | IdentityAdvanced | Medium |
| R290 | Citrix Gateway Exploit Probe | IdentityAdvanced | High |
| R291 | Fortinet SSL VPN Exploit Probe | IdentityAdvanced | High |
| R292 | Palo Alto GlobalProtect Exploit Probe | IdentityAdvanced | High |
| R293 | Kubernetes Anonymous API Discovery Probe | KubernetesContainer | High |
| R294 | Kubernetes Secrets API Access Probe | KubernetesContainer | Critical |
| R295 | Kubernetes Exec Into Pod Over API | KubernetesContainer | Critical |
| R296 | Kubernetes PortForward Abuse Indicator | KubernetesContainer | High |
| R297 | Kubernetes ServiceAccount Token Exfil | KubernetesContainer | Critical |
| R298 | Container Runtime Socket Exposure Probe | KubernetesContainer | Critical |
| R299 | Docker Remote API Container Create | KubernetesContainer | Critical |
| R300 | Kubernetes Etcd Client Access External | KubernetesContainer | Critical |
| R301 | Kubelet Readonly Port Probe | KubernetesContainer | High |
| R302 | Kubelet Run Or Exec Probe | KubernetesContainer | Critical |
| R303 | Container Registry Manifest Enumeration | KubernetesContainer | Medium |
| R304 | Container Registry Anonymous Pull Burst | KubernetesContainer | Medium |
| R305 | Image Registry Push From Workstation | KubernetesContainer | High |
| R306 | Docker Build Context Archive Upload | KubernetesContainer | High |
| R307 | Kubernetes Dashboard Exposure Probe | KubernetesContainer | High |
| R308 | Helm Tiller Legacy Port Exposure | KubernetesContainer | High |
| R309 | Istio Envoy Admin Endpoint Probe | KubernetesContainer | High |
| R310 | Service Mesh Sidecar Bypass Pattern | KubernetesContainer | Medium |
| R311 | Cloud Workload Metadata Token Request | KubernetesContainer | Critical |
| R312 | Kubernetes Network Policy Bypass Indicator | KubernetesContainer | High |
| R313 | Direct SMTP To MX From Workstation | EmailCollaboration | High |
| R314 | SMTP Authentication Failure Burst | EmailCollaboration | Medium |
| R315 | IMAP Login Failure Spray | EmailCollaboration | Medium |
| R316 | POP3 Cleartext Credential Exposure | EmailCollaboration | High |
| R317 | Exchange Autodiscover External Spray | EmailCollaboration | Medium |
| R318 | EWS Enumeration Burst | EmailCollaboration | Medium |
| R319 | OWA Admin Or ECP Probe | EmailCollaboration | High |
| R320 | M365 Graph Mail Export Pattern | EmailCollaboration | High |
| R321 | Gmail API Bulk Message Read | EmailCollaboration | High |
| R322 | Mail Forwarding Rule Creation Indicator | EmailCollaboration | High |
| R323 | Suspicious Attachment Download Burst | EmailCollaboration | Medium |
| R324 | Phishing Kit URI Pattern | EmailCollaboration | High |
| R325 | Lookalike Sender Domain Contact | EmailCollaboration | Medium |
| R326 | DMARC SPF DKIM Recon Query Burst | EmailCollaboration | Low |
| R327 | Slack OAuth App Install Callback | EmailCollaboration | Medium |
| R328 | Teams Webhook Abuse Indicator | EmailCollaboration | High |
| R329 | SharePoint Bulk Download Pattern | EmailCollaboration | High |
| R330 | OneDrive Anonymous Share Link Mass Access | EmailCollaboration | Medium |
| R331 | Calendar Invite Phishing Link Pattern | EmailCollaboration | Medium |
| R332 | Email Archive Export Download | EmailCollaboration | High |
| R333 | SMB Null Session Enumeration | ActiveDirectoryWindows | High |
| R334 | SMB Named Pipe Enumeration Burst | ActiveDirectoryWindows | Medium |
| R335 | LSARPC SAMR Enumeration Pattern | ActiveDirectoryWindows | High |
| R336 | DRSUAPI Replication Attempt | ActiveDirectoryWindows | Critical |
| R337 | Kerberos S4U Delegation Abuse Indicator | ActiveDirectoryWindows | High |
| R338 | Kerberos RC4 Downgrade Indicator | ActiveDirectoryWindows | Medium |
| R339 | SMB Signing Disabled Sensitive Host | ActiveDirectoryWindows | High |
| R340 | Remote Registry Service Access | ActiveDirectoryWindows | Medium |
| R341 | Scheduled Task Remote Creation Pattern | ActiveDirectoryWindows | High |
| R342 | Windows Admin Center Exposure Probe | ActiveDirectoryWindows | High |
| R343 | PowerShell Remoting Encoded Command | ActiveDirectoryWindows | High |
| R344 | WMI Event Subscription Remote Pattern | ActiveDirectoryWindows | High |
| R345 | DCOM MMC20 Lateral Indicator | ActiveDirectoryWindows | High |
| R346 | MSSQL xp_cmdshell Use Indicator | ActiveDirectoryWindows | Critical |
| R347 | MSSQL Linked Server Enumeration | ActiveDirectoryWindows | Medium |
| R348 | LDAP AdminSDHolder Recon | ActiveDirectoryWindows | Medium |
| R349 | LDAP Kerberoast SPN Enumeration | ActiveDirectoryWindows | High |
| R350 | LDAP Password Policy Recon | ActiveDirectoryWindows | Low |
| R351 | NTLM Authentication To External Host | ActiveDirectoryWindows | High |
| R352 | LLMNR NBNS Responder Tool Indicator | ActiveDirectoryWindows | High |
| R353 | GitHub Personal Access Token In Traffic | DevOpsSupplyChain | Critical |
| R354 | GitLab Private Token In Traffic | DevOpsSupplyChain | Critical |
| R355 | Jenkins Script Console Probe | DevOpsSupplyChain | High |
| R356 | Jenkins Crumb Issuer Enumeration | DevOpsSupplyChain | Medium |
| R357 | TeamCity Auth Bypass Probe | DevOpsSupplyChain | High |
| R358 | Bamboo Build Artifact Bulk Download | DevOpsSupplyChain | Medium |
| R359 | Azure DevOps PAT In URL | DevOpsSupplyChain | Critical |
| R360 | CircleCI API Token Exposure | DevOpsSupplyChain | High |
| R361 | GitHub Actions OIDC Token Request | DevOpsSupplyChain | High |
| R362 | GitHub Actions Runner Registration Token | DevOpsSupplyChain | High |
| R363 | CI Artifact Archive Download Burst | DevOpsSupplyChain | High |
| R364 | Secrets Manager API Enumeration | DevOpsSupplyChain | High |
| R365 | HashiCorp Vault Token In HTTP | DevOpsSupplyChain | Critical |
| R366 | Vault Transit Decrypt Burst | DevOpsSupplyChain | High |
| R367 | Terraform Cloud Token Exposure | DevOpsSupplyChain | High |
| R368 | Docker Hub Pull Storm | DevOpsSupplyChain | Medium |
| R369 | NPM Token Exposure | DevOpsSupplyChain | Critical |
| R370 | PyPI Credential Upload Attempt | DevOpsSupplyChain | High |
| R371 | Maven Repository Credential Use | DevOpsSupplyChain | High |
| R372 | Dependency Confusion Package Name Pattern | DevOpsSupplyChain | Medium |
| R373 | AWS STS AssumeRole Burst | CloudInfrastructure | High |
| R374 | AWS IAM AccessKey In URL | CloudInfrastructure | Critical |
| R375 | AWS S3 ListBuckets External | CloudInfrastructure | Medium |
| R376 | AWS S3 GetObject Bulk Download | CloudInfrastructure | High |
| R377 | AWS EC2 UserData Metadata Probe | CloudInfrastructure | Critical |
| R378 | AWS Lambda Invoke Burst | CloudInfrastructure | Medium |
| R379 | AWS CloudTrail StopLogging Indicator | CloudInfrastructure | Critical |
| R380 | AWS GuardDuty Finding Exfil Indicator | CloudInfrastructure | High |
| R381 | Azure ARM Token Request Burst | CloudInfrastructure | Medium |
| R382 | Azure KeyVault Secret Enumeration | CloudInfrastructure | High |
| R383 | Azure Storage SAS Token In URL | CloudInfrastructure | High |
| R384 | Azure IMDS Token Request | CloudInfrastructure | Critical |
| R385 | GCP OAuth Scope Broad Request | CloudInfrastructure | High |
| R386 | GCP Storage SignedURL Mass Access | CloudInfrastructure | High |
| R387 | GCP ServiceAccount Key Download | CloudInfrastructure | Critical |
| R388 | Cloudflare Tunnel Creation Indicator | CloudInfrastructure | High |
| R389 | Ngrok Tunnel Creation Or Auth | CloudInfrastructure | High |
| R390 | Tailscale Tailnet Auth Indicator | CloudInfrastructure | Medium |
| R391 | ZeroTier Network Join Indicator | CloudInfrastructure | Medium |
| R392 | Public Cloud CLI UserAgent From Server | CloudInfrastructure | Medium |
| R393 | Cobalt Strike Beacon URI Pattern | MalwareC2 | Critical |
| R394 | Cobalt Strike Malleable C2 Header Pattern | MalwareC2 | Critical |
| R395 | Sliver C2 MTLS Pattern | MalwareC2 | Critical |
| R396 | Mythic Agent Callback Pattern | MalwareC2 | High |
| R397 | Metasploit Meterpreter Stager Pattern | MalwareC2 | Critical |
| R398 | Havoc C2 Callback Pattern | MalwareC2 | Critical |
| R399 | Brute Ratel Badger Pattern | MalwareC2 | Critical |
| R400 | Covenant Grunt Callback Pattern | MalwareC2 | High |
| R401 | Empire Stager URI Pattern | MalwareC2 | High |
| R402 | AsyncRAT Telegram C2 Pattern | MalwareC2 | High |
| R403 | Remcos RAT C2 Pattern | MalwareC2 | High |
| R404 | AgentTesla SMTP Exfil Pattern | MalwareC2 | High |
| R405 | QakBot URI Pattern | MalwareC2 | High |
| R406 | Emotet Loader URI Pattern | MalwareC2 | High |
| R407 | Bumblebee Loader URI Pattern | MalwareC2 | High |
| R408 | SocGholish FakeUpdate Pattern | MalwareC2 | High |
| R409 | Raspberry Robin Short LNK Pattern | MalwareC2 | Medium |
| R410 | Redline Stealer Exfil Pattern | MalwareC2 | High |
| R411 | Lumma Stealer Gate Pattern | MalwareC2 | High |
| R412 | Generic Beacon Jitter Low Variance | MalwareC2 | Medium |
| R413 | Citrix Netscaler Gateway Scan Pattern | NetworkApplianceExposure | High |
| R414 | Ivanti Connect Secure Exploit Probe | NetworkApplianceExposure | High |
| R415 | F5 BIG-IP TMUI Probe | NetworkApplianceExposure | High |
| R416 | SonicWall SSLVPN Exploit Probe | NetworkApplianceExposure | High |
| R417 | Cisco ASA WebVPN Probe | NetworkApplianceExposure | High |
| R418 | MikroTik Winbox External Access | NetworkApplianceExposure | High |
| R419 | Ubiquiti Discovery External Exposure | NetworkApplianceExposure | Medium |
| R420 | QNAP QTS Admin Probe | NetworkApplianceExposure | High |
| R421 | Synology DSM Admin Probe | NetworkApplianceExposure | High |
| R422 | VMware vCenter SOAP Probe | NetworkApplianceExposure | High |
| R423 | VMware ESXi Hostd Probe | NetworkApplianceExposure | High |
| R424 | Proxmox API Exposure Probe | NetworkApplianceExposure | High |
| R425 | Apache Solr Admin Probe | NetworkApplianceExposure | High |
| R426 | Elasticsearch Cluster Info External | NetworkApplianceExposure | High |
| R427 | Kibana Console Exposure | NetworkApplianceExposure | High |
| R428 | Grafana Admin Login Probe | NetworkApplianceExposure | Medium |
| R429 | Prometheus Metrics Exposure External | NetworkApplianceExposure | Medium |
| R430 | Jupyter Notebook Token Probe | NetworkApplianceExposure | High |
| R431 | Airflow Admin Endpoint Probe | NetworkApplianceExposure | High |
| R432 | Consul Nomad Admin Probe | NetworkApplianceExposure | High |
| R433 | PostgreSQL External Login Attempt | DatabaseServiceExposure | High |
| R434 | MySQL External Login Attempt | DatabaseServiceExposure | High |
| R435 | MSSQL External Login Attempt | DatabaseServiceExposure | High |
| R436 | MongoDB External Exposure Probe | DatabaseServiceExposure | High |
| R437 | Redis CONFIG SET Indicator | DatabaseServiceExposure | Critical |
| R438 | Redis Replication Abuse Indicator | DatabaseServiceExposure | Critical |
| R439 | Memcached Stats Enumeration | DatabaseServiceExposure | Medium |
| R440 | Elasticsearch Snapshot Repository Probe | DatabaseServiceExposure | High |
| R441 | Cassandra CQL External Probe | DatabaseServiceExposure | High |
| R442 | Oracle TNS Enumeration | DatabaseServiceExposure | High |
| R443 | CouchDB Admin Probe | DatabaseServiceExposure | High |
| R444 | InfluxDB Query Endpoint Exposure | DatabaseServiceExposure | High |
| R445 | ClickHouse HTTP SQL Probe | DatabaseServiceExposure | High |
| R446 | Neo4j Browser Exposure Probe | DatabaseServiceExposure | High |
| R447 | RabbitMQ Management Probe | DatabaseServiceExposure | High |
| R448 | Kafka Broker External Access | DatabaseServiceExposure | High |
| R449 | Zookeeper Four Letter Word Probe | DatabaseServiceExposure | Medium |
| R450 | NATS Broker External Access | DatabaseServiceExposure | High |
| R451 | MQTT Anonymous Login Pattern | DatabaseServiceExposure | High |
| R452 | Database Large Result Export Pattern | DatabaseServiceExposure | High |
| R453 | mDNS Service Enumeration High Rate | LocalDiscoveryWireless | Medium |
| R454 | SSDP MSEARCH External Answer | LocalDiscoveryWireless | Medium |
| R455 | AirPlay Discovery From Non Media Host | LocalDiscoveryWireless | Low |
| R456 | Chromecast Discovery Burst | LocalDiscoveryWireless | Low |
| R457 | Printer JetDirect External Access | LocalDiscoveryWireless | Medium |
| R458 | IPP Printing From External Host | LocalDiscoveryWireless | Medium |
| R459 | SMB Browse Election Anomaly | LocalDiscoveryWireless | Low |
| R460 | NetBIOS Name Query Sweep | LocalDiscoveryWireless | Medium |
| R461 | DHCP Starvation Candidate | LocalDiscoveryWireless | High |
| R462 | DHCP Rogue Offer Detected | LocalDiscoveryWireless | High |
| R463 | ARP Gratuitous Storm | LocalDiscoveryWireless | Medium |
| R464 | ARP Duplicate MAC FlipFlop | LocalDiscoveryWireless | High |
| R465 | IPv6 SLAAC Prefix Change | LocalDiscoveryWireless | Medium |
| R466 | WiFi Controller Admin Probe | LocalDiscoveryWireless | High |
| R467 | CAPWAP External Controller Attempt | LocalDiscoveryWireless | High |
| R468 | Bluetooth Gateway Internet Egress | LocalDiscoveryWireless | Medium |
| R469 | Android Debug Bridge Network Access | LocalDiscoveryWireless | High |
| R470 | Mobile MDM Enrollment Burst | LocalDiscoveryWireless | Medium |
| R471 | RDP Clipboard File Transfer Indicator | LocalDiscoveryWireless | Medium |
| R472 | Remote Support Tool Unexpected Use | LocalDiscoveryWireless | Medium |
| R473 | Modbus Function43 DeviceId Enumeration | OtIcsDeep | Medium |
| R474 | Modbus Force Listen Only Mode Attempt | OtIcsDeep | Critical |
| R475 | Modbus Diagnostics Function Abuse | OtIcsDeep | High |
| R476 | Modbus Coil Write Burst | OtIcsDeep | Critical |
| R477 | S7 Start Stop CPU Command Indicator | OtIcsDeep | Critical |
| R478 | S7 Upload Download Block Transfer | OtIcsDeep | Critical |
| R479 | S7 PLC Identification Probe | OtIcsDeep | Medium |
| R480 | DNP3 Control Relay Output Block | OtIcsDeep | Critical |
| R481 | DNP3 Freeze Counter Command | OtIcsDeep | High |
| R482 | IEC104 Control Command External | OtIcsDeep | Critical |
| R483 | OPC UA Browse Node Burst | OtIcsDeep | Medium |
| R484 | OPC UA Write Request Indicator | OtIcsDeep | Critical |
| R485 | BACnet WriteProperty Request | OtIcsDeep | Critical |
| R486 | BACnet DeviceCommunicationControl | OtIcsDeep | Critical |
| R487 | Profinet DCP Set Name Request | OtIcsDeep | High |
| R488 | EtherNetIP ListIdentity Burst | OtIcsDeep | Medium |
| R489 | EtherNetIP ForwardOpen External | OtIcsDeep | Critical |
| R490 | IEC61850 MMS Write Indicator | OtIcsDeep | Critical |
| R491 | GOOSE Multicast Outside Substation | OtIcsDeep | Critical |
| R492 | Historian Bulk Query From Workstation | OtIcsDeep | High |
| R493 | Browser Password Store File Upload | DataLossStaging | Critical |
| R494 | SSH Private Key Upload | DataLossStaging | Critical |
| R495 | KeePass Database Upload | DataLossStaging | Critical |
| R496 | VPN Config File Upload | DataLossStaging | High |
| R497 | Browser Cookie Database Upload | DataLossStaging | Critical |
| R498 | Large Clipboard Sync Upload | DataLossStaging | Medium |
| R499 | Remote Desktop File Transfer Burst | DataLossStaging | High |
| R500 | Compressed Archive Then Cloud Upload | DataLossStaging | High |
| R501 | Multipart Form Data High Entropy Filename | DataLossStaging | High |
| R502 | Data URI Base64 POST Large | DataLossStaging | High |
| R503 | Pastebin Raw POST Bulk | DataLossStaging | High |
| R504 | GitHub Gist Secret Post | DataLossStaging | High |
| R505 | Discord Attachment Upload Burst | DataLossStaging | High |
| R506 | Telegram Document Exfil Burst | DataLossStaging | High |
| R507 | Mega NZ Upload Pattern | DataLossStaging | High |
| R508 | Rclone UserAgent Egress | DataLossStaging | High |
| R509 | Rsync External Push | DataLossStaging | High |
| R510 | S3 Compatible Unknown Endpoint Upload | DataLossStaging | High |
| R511 | DB Client Export Then HTTP Upload | DataLossStaging | Critical |
| R512 | Sensitive Filename To Personal Email | DataLossStaging | High |
| R513 | SSH Dynamic SOCKS Proxy Use | EvasionTunnel | High |
| R514 | Chisel Tunnel Handshake | EvasionTunnel | High |
| R515 | FRP Tunnel Handshake | EvasionTunnel | High |
| R516 | Cloudflared Tunnel Handshake | EvasionTunnel | High |
| R517 | Ngrok Tunnel Handshake V2 | EvasionTunnel | High |
| R518 | Reverse SSH Tunnel Pattern | EvasionTunnel | High |
| R519 | DNS Over QUIC Unapproved Resolver | EvasionTunnel | High |
| R520 | MASQUE CONNECT UDP Proxy Use | EvasionTunnel | Medium |
| R521 | HTTP CONNECT To Non Proxy Port | EvasionTunnel | Medium |
| R522 | WebSocket Tunnel To IP Literal | EvasionTunnel | High |
| R523 | Domain Fronting Host SNI Mismatch | EvasionTunnel | High |
| R524 | ECH To Unapproved Provider | EvasionTunnel | Medium |
| R525 | QUIC Connection ID Rotation Burst | EvasionTunnel | Medium |
| R526 | Packet Size Mimicry Beacon | EvasionTunnel | Medium |
| R527 | Sleepy Beacon Long Gap Pattern | EvasionTunnel | Medium |
| R528 | User Agent Randomization Burst | EvasionTunnel | Medium |
| R529 | Sensor Heartbeat Missing For Site | PlatformHealthAdvanced | High |
| R530 | Sensor Clock Skew Increasing | PlatformHealthAdvanced | Medium |
| R531 | Detection Journal Disk Space Low | PlatformHealthAdvanced | Critical |
| R532 | Outbox Retry Storm | PlatformHealthAdvanced | High |
| R533 | Rule Match Volume Anomaly | PlatformHealthAdvanced | Medium |
| R534 | Rule Silent Unexpectedly | PlatformHealthAdvanced | Medium |
| R535 | Telemetry Field Coverage Drop | PlatformHealthAdvanced | High |
| R536 | Parser Error Spike | PlatformHealthAdvanced | High |
| R537 | GeoIP Lookup Failure Spike | PlatformHealthAdvanced | Low |
| R538 | Reputation Lookup Failure Spike | PlatformHealthAdvanced | Low |
| R539 | Baseline Store Write Failure | PlatformHealthAdvanced | High |
| R540 | Feedback Store Write Failure | PlatformHealthAdvanced | Medium |
| R541 | Content Pack Validation Failure | PlatformHealthAdvanced | Medium |
| R542 | Replay Benchmark Regression | PlatformHealthAdvanced | High |
| R543 | Rule Config Profile Drift | PlatformHealthAdvanced | Medium |
| R544 | Excessive Suppression Ratio | PlatformHealthAdvanced | Medium |

## Safety model

- R001-R272 remain unchanged by ID.
- R273-R544 are explicitly registered classes under `Engine/Rules/Expansion`.
- The rules rely on observable packet, flow, HTTP, DNS, TLS, process, WHOIS, enrichment, or platform-health text fields.
- Missing telemetry produces `NoMatch`; the implementation does not fabricate detections.
- All new rules inherit `TelemetryDetectionRuleBase`, so they automatically participate in RuleIntelligence, telemetry validation, confidence/evidence enrichment, journaling, rule modes, profiles, hunting, triage, and benchmark infrastructure.
