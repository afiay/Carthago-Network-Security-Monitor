# R123-R272 Selected Detection Rule Expansion

This pack adds 150 concrete, telemetry-safe rules selected to improve Carthago coverage across identity edge access, TLS/PKI, HTTP/API exploitation, DNS/C2, cloud/SaaS/dev-tool abuse, IoT/OT, exfiltration, and evasion/infrastructure anomalies.

The rules are not placeholders. Each rule has a dedicated file under `Engine/Rules/Expansion/`, is explicitly registered in `RuleRegistry`, uses the shared telemetry detector in `ExtendedRuleDetectors`, and returns `NoMatch` when observable evidence is absent.

| Rule | Name | Category | Default severity |
|---|---|---|---|
| R123 | Suspicious VPN Login Path | IdentityAccess | High |
| R124 | External RDP Exposure Attempt | IdentityAccess | High |
| R125 | External WinRM Exposure Attempt | IdentityAccess | High |
| R126 | External SSH Brute Candidate | IdentityAccess | High |
| R127 | Admin Portal Access From Internet | IdentityAccess | High |
| R128 | Network Appliance Management Exposure | IdentityAccess | High |
| R129 | Suspicious SAML OIDC Callback Traffic | IdentityAccess | Medium |
| R130 | Credential Stuffing Against Web Login | IdentityAccess | High |
| R131 | HTTP Authentication Failure Spike | IdentityAccess | Medium |
| R132 | Rapid Country Change For Source Identity | IdentityAccess | Medium |
| R133 | Basic Authentication Over Cleartext | IdentityAccess | High |
| R134 | API Token In URL Query | IdentityAccess | High |
| R135 | Bearer Token Over Cleartext HTTP | IdentityAccess | High |
| R136 | Session Cookie Over Cleartext HTTP | IdentityAccess | Medium |
| R137 | Password Reset Or Enrollment Spike | IdentityAccess | Medium |
| R138 | Self-Signed Certificate To External Host | TlsPki | Medium |
| R139 | Weak TLS Version Observed | TlsPki | High |
| R140 | Suspicious Certificate Issuer Pattern | TlsPki | Medium |
| R141 | New SNI With Rare TLS Fingerprint | TlsPki | Medium |
| R142 | TLS Certificate Subject SNI Mismatch | TlsPki | Medium |
| R143 | Wildcard Certificate On Sensitive Service | TlsPki | Medium |
| R144 | Certificate Validity Period Too Long | TlsPki | Medium |
| R145 | Short-Lived Certificate With New SNI | TlsPki | Medium |
| R146 | TLS Handshake Failure Spike | TlsPki | Medium |
| R147 | Encrypted ClientHello Or ECH Indicator | TlsPki | Low |
| R148 | TLS To Dynamic DNS Host | TlsPki | Medium |
| R149 | IP Literal Used As TLS Name | TlsPki | Medium |
| R150 | Known Malware-Like TLS Fingerprint Label | TlsPki | High |
| R151 | HTTP2 ALPN On Uncommon Port | TlsPki | Medium |
| R152 | TLS Fingerprint Fan-Out To Many ASNs | TlsPki | Medium |
| R153 | GraphQL Introspection Query | HttpApi | Medium |
| R154 | GraphQL Batching Abuse | HttpApi | Medium |
| R155 | REST API Enumeration Burst | HttpApi | Medium |
| R156 | JWT None Algorithm Indicator | HttpApi | High |
| R157 | JWT In URL Query | HttpApi | Medium |
| R158 | Swagger OpenAPI Exposure Probe | HttpApi | Medium |
| R159 | Spring Actuator Exposure Probe | HttpApi | High |
| R160 | Kubernetes API Probe | HttpApi | High |
| R161 | Docker API TCP Exposure Probe | HttpApi | High |
| R162 | Redis Memcached Web Probe | HttpApi | Medium |
| R163 | SSRF Metadata Service Probe | HttpApi | Critical |
| R164 | Open Redirect Parameter Abuse | HttpApi | Medium |
| R165 | PHPInfo Exposure Probe | HttpApi | Low |
| R166 | Environment File Secret Probe | HttpApi | High |
| R167 | Git Directory Exposure Probe | HttpApi | High |
| R168 | Backup Archive Download Probe | HttpApi | Medium |
| R169 | Admin Login Brute Indicator | HttpApi | Medium |
| R170 | XXE Payload Indicator | HttpApi | High |
| R171 | SOAP Action Exploit Pattern | HttpApi | Medium |
| R172 | Scanner User Agent With Browser Claim Mismatch | HttpApi | Low |
| R173 | Suspicious CORS Preflight To Admin API | HttpApi | Medium |
| R174 | WebDAV Method Abuse | HttpApi | Medium |
| R175 | HTTP Request Smuggling Indicator | HttpApi | High |
| R176 | Host Header Injection Indicator | HttpApi | Medium |
| R177 | High-Risk File Upload Extension | HttpApi | High |
| R178 | DNS Query For Crypto Mining Pool | DnsAdvanced | High |
| R179 | DNS Query For Tor Onion Gateway | DnsAdvanced | Medium |
| R180 | DNS Query To High-Risk TLD | DnsAdvanced | Low |
| R181 | Excessive DNS ANY Queries | DnsAdvanced | Medium |
| R182 | DNS Zone Transfer Attempt | DnsAdvanced | High |
| R183 | DNSSEC Random Subdomain Spike | DnsAdvanced | Medium |
| R184 | External Reverse DNS Enumeration | DnsAdvanced | Medium |
| R185 | Canary Or Metadata Domain Probe | DnsAdvanced | Low |
| R186 | DNS CAA Record Probing Burst | DnsAdvanced | Low |
| R187 | DNS NULL Query Usage | DnsAdvanced | Medium |
| R188 | Active Directory SRV Enumeration | DnsAdvanced | Medium |
| R189 | AD SRV Query To External Resolver | DnsAdvanced | High |
| R190 | DNS Short TTL Burst | DnsAdvanced | Medium |
| R191 | Consonant-Heavy DGA Domain | DnsAdvanced | Medium |
| R192 | Punycode Homograph Domain | DnsAdvanced | Medium |
| R193 | Cloud Brand Lookalike Domain | DnsAdvanced | Medium |
| R194 | DoH Over Uncommon Host | DnsAdvanced | Medium |
| R195 | DNS Over TLS To Unapproved Resolver | DnsAdvanced | High |
| R196 | NXDOMAIN Unique Root Spike | DnsAdvanced | Medium |
| R197 | DNS Rebinding Private IP Answer | DnsAdvanced | High |
| R198 | AWS Metadata Credential Retrieval | CloudDev | Critical |
| R199 | GCP Metadata Credential Retrieval | CloudDev | Critical |
| R200 | Azure Metadata Credential Retrieval | CloudDev | Critical |
| R201 | Kubernetes Service Account Token Access | CloudDev | Critical |
| R202 | Docker Registry Push Pull Anomaly | CloudDev | Medium |
| R203 | Container Image Layer Bulk Download | CloudDev | Medium |
| R204 | Terraform State File Access | CloudDev | High |
| R205 | CI CD Secret Token In URL | CloudDev | High |
| R206 | Git Clone From Unknown External Host | CloudDev | Medium |
| R207 | Git Push To Unknown External Host | CloudDev | High |
| R208 | Package Manager To Suspicious Registry | CloudDev | Medium |
| R209 | NPM Install Script Beacon Pattern | CloudDev | High |
| R210 | PyPI Package Download From Rare Domain | CloudDev | Medium |
| R211 | PowerShell Gallery External Script Pull | CloudDev | High |
| R212 | Curl Wget Raw Script To Shell | CloudDev | Critical |
| R213 | Cloud Storage Presigned URL Mass Access | CloudDev | High |
| R214 | S3 Bucket Listing Probe | CloudDev | Medium |
| R215 | Azure Blob Container Enumeration | CloudDev | Medium |
| R216 | Google Storage Bucket Enumeration | CloudDev | Medium |
| R217 | Slack Webhook Exfiltration | CloudDev | High |
| R218 | Discord Webhook File Upload | CloudDev | High |
| R219 | Telegram Bot API Send Document | CloudDev | High |
| R220 | Paste Service High Volume POST | CloudDev | High |
| R221 | Remote Desktop SaaS Tool Beacon | CloudDev | Medium |
| R222 | Unauthorized Overlay Network Egress | CloudDev | High |
| R223 | ICS Protocol To Internet | IotOtAdvanced | Critical |
| R224 | DNP3 Traffic Outside Approved Segment | IotOtAdvanced | High |
| R225 | S7comm Traffic Outside Approved Segment | IotOtAdvanced | High |
| R226 | EtherNetIP CIP Discovery Burst | IotOtAdvanced | Medium |
| R227 | Profinet DCP Discovery Suspicious | IotOtAdvanced | Medium |
| R228 | OPC UA Internet Egress | IotOtAdvanced | High |
| R229 | MQTT Retained Topic Abuse | IotOtAdvanced | Medium |
| R230 | MQTT Last Will Suspicious | IotOtAdvanced | Medium |
| R231 | CoAP Multicast Discovery Burst | IotOtAdvanced | Medium |
| R232 | mDNS Service Enumeration Burst | IotOtAdvanced | Medium |
| R233 | Printer Admin Protocol External Access | IotOtAdvanced | Medium |
| R234 | IP Camera RTSP External Stream | IotOtAdvanced | High |
| R235 | ONVIF Discovery From Workstation | IotOtAdvanced | Medium |
| R236 | IoT Firmware Update Over Cleartext | IotOtAdvanced | High |
| R237 | IoT Default Web Admin Access | IotOtAdvanced | High |
| R238 | Smart Home Hub Cloud Burst | IotOtAdvanced | Medium |
| R239 | Zigbee2MQTT Bridge Internet Access | IotOtAdvanced | High |
| R240 | Modbus Write Function | IotOtAdvanced | Critical |
| R241 | BACnet Who-Is I-Am Burst | IotOtAdvanced | Medium |
| R242 | NTP Amplification Candidate | IotOtAdvanced | Medium |
| R243 | Large Outbound Archive Transfer | ExfiltrationAdvanced | High |
| R244 | Database Dump Filename Transfer | ExfiltrationAdvanced | Critical |
| R245 | Sensitive File Extension Upload | ExfiltrationAdvanced | High |
| R246 | Source Code Archive Upload | ExfiltrationAdvanced | High |
| R247 | SSH SCP High Volume Egress | ExfiltrationAdvanced | High |
| R248 | FTP Upload To External Host | ExfiltrationAdvanced | High |
| R249 | SMB Upload To External Host | ExfiltrationAdvanced | Critical |
| R250 | Large HTTP POST To IP Literal | ExfiltrationAdvanced | High |
| R251 | Multipart Upload To Unknown Domain | ExfiltrationAdvanced | High |
| R252 | High Entropy Outbound URI Path | ExfiltrationAdvanced | Medium |
| R253 | Base64 Blob In HTTP POST | ExfiltrationAdvanced | High |
| R254 | Repeated Small Chunk Uploads | ExfiltrationAdvanced | High |
| R255 | Off-Hours Bulk Egress Indicator | ExfiltrationAdvanced | Medium |
| R256 | Internal Data Staging Server Behavior | ExfiltrationAdvanced | High |
| R257 | Exfiltration After Credential Alert Chain | ExfiltrationAdvanced | Critical |
| R258 | ICMP Destination Unreachable Spike | EvasionInfra | Medium |
| R259 | TCP Reset Storm | EvasionInfra | Medium |
| R260 | Rare TCP Option Fingerprint | EvasionInfra | Medium |
| R261 | TTL Anomaly To Same Service | EvasionInfra | Low |
| R262 | Suspicious Packet Fragmentation | EvasionInfra | High |
| R263 | User-Space Proxy Process Egress | EvasionInfra | Medium |
| R264 | Tor Directory Or Guard Connection | EvasionInfra | High |
| R265 | Public VPN Proxy Domain Contact | EvasionInfra | Medium |
| R266 | New Process Initiating Network Egress | EvasionInfra | Low |
| R267 | Suspicious Process Name Network Egress | EvasionInfra | High |
| R268 | DNS Or HTTP From Script Interpreter | EvasionInfra | High |
| R269 | Security Tool Update Block Indicator | EvasionInfra | Medium |
| R270 | Detection Pipeline Tampering Indicator | EvasionInfra | Critical |
| R271 | Threat Feed IOC With Low Reputation Overlap | EvasionInfra | Critical |
| R272 | Multi-Signal Rule Stack Surge From Host | EvasionInfra | High |

## Selection logic

The expansion prioritizes behavior families with high practical value for NDR/SIEM/SOAR workflows:

- identity and edge-service abuse
- exploitable HTTP/API exposure
- cloud metadata and dev-tool secret access
- DNS command-and-control and domain abuse
- cloud/SaaS exfiltration paths
- IoT/OT protocol misuse
- data staging and outbound transfer patterns
- evasion, proxying, and detection-pipeline tampering indicators

Each rule is deterministic and evidence-led. No rule invents detections when required telemetry is absent.
