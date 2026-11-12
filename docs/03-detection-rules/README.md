# Detection rules

Rule-authoring contracts, catalog guides, content packs and every historical rule batch.

[Documentation home](../README.md)

## Working source of truth

- **[Master detection-rule catalog](MASTER_RULE_CATALOG.md)** — every registered RNNN rule, direct source links and historical evidence
- [Rule hardening progress ledger](../RULE_HARDENING_PROGRESS.md)
- [Rule documentation standard](../rules/RULE_DOCUMENTATION_STANDARD.md)
- [Content-pack overview](content-packs/README.md)
- [Detection expansion cursor](../rules/DETECTION_EXPANSION_CANDIDATE_CURSOR_20261103.md)
- [Unified 2,500-rule admission cursor](../rules/UNIFIED_2500_RULE_ADMISSION_CURSOR.md)
- [Protocol-informed backlog](../rules/PROTOCOL_INFORMED_THREAT_BACKLOG.md)

The master catalog is the central entry point; batch files remain historical *source-candidate evidence*, not proof of a green runtime or holdout. Two separate R001–R005 documents were retained because they represent distinct historical records. Active automations may initially write new batches at the original `docs/RULE_BATCH_*` paths; the catalog links those too.

## Guides and reports

- [CATALOG WIDE RULE HARDENING](CATALOG_WIDE_RULE_HARDENING.md)
- [MASTER RULE CATALOG](MASTER_RULE_CATALOG.md)

## Content packs

- [ActiveDirectoryPack](content-packs/ActiveDirectoryPack.md)
- [CloudSaasPack](content-packs/CloudSaasPack.md)
- [DevOpsPack](content-packs/DevOpsPack.md)
- [ExfiltrationPack](content-packs/ExfiltrationPack.md)
- [IoTHomePack](content-packs/IoTHomePack.md)
- [KubernetesPack](content-packs/KubernetesPack.md)
- [MalwareC2Pack](content-packs/MalwareC2Pack.md)
- [Microsoft365Pack](content-packs/Microsoft365Pack.md)
- [OTIndustrialPack](content-packs/OTIndustrialPack.md)

## Engineering guides

- [AddingDetectionRules](guides/AddingDetectionRules.md)
- [ContentPacks](guides/ContentPacks.md)
- [DetectionEngineeringModel](guides/DetectionEngineeringModel.md)
- [R123 R272 SelectedRules](guides/R123_R272_SelectedRules.md)
- [R273 R544 SelectedRules](guides/R273_R544_SelectedRules.md)
- [ResearchBackedDetectionRules](guides/ResearchBackedDetectionRules.md)
- [RuleMetadata](guides/RuleMetadata.md)
- [RuleOwnedPrecisionDetectorMigration](guides/RuleOwnedPrecisionDetectorMigration.md)
- [RulePrecisionProfiles](guides/RulePrecisionProfiles.md)
- [RuleProfiles](guides/RuleProfiles.md)

## Rule-batch evidence

[Browse the complete historical index](batches/README.md) — grouped by starting ID; all original records are preserved.
