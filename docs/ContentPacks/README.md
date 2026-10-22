# Carthago Content Packs

Carthago keeps the local JSONL detection journal as the source of truth and layers optional compiled content packs on top of the immutable core rule set. These packs are explicit, profile-aware, benchmarkable, and safe by default.

Available packs:

- [CloudSaasPack.md](./CloudSaasPack.md): `carthago.cloud-saas.v1`, 50 rules, `CLOUD001-CLOUD050`
- [ActiveDirectoryPack.md](./ActiveDirectoryPack.md): `carthago.active-directory.v1`, 50 rules, `AD001-AD050`
- [KubernetesPack.md](./KubernetesPack.md): `carthago.kubernetes.v1`, 40 rules, `K8S001-K8S040`
- [Microsoft365Pack.md](./Microsoft365Pack.md): `carthago.microsoft365.v1`, 40 rules, `M365001-M365040`
- [DevOpsPack.md](./DevOpsPack.md): `carthago.devops.v1`, 40 rules, `DEVOPS001-DEVOPS040`
- [IoTHomePack.md](./IoTHomePack.md): `carthago.iot-home.v1`, 40 rules, `IOT001-IOT040`
- [OTIndustrialPack.md](./OTIndustrialPack.md): `carthago.ot-industrial.v1`, 50 rules, `OT001-OT050`
- [MalwareC2Pack.md](./MalwareC2Pack.md): `carthago.malware-c2.v1`, 60 rules, `C2001-C2060`
- [ExfiltrationPack.md](./ExfiltrationPack.md): `carthago.exfiltration.v1`, 40 rules, `EXFIL001-EXFIL040`

Content-pack lifecycle:

- Dry run validates the manifest, calculates rule and tuning impact, and records plan history without enabling anything.
- Install persists the manifest and install state under `%ProgramData%\Carthago\content-packs\` by default.
- Enable activates only the selected pack’s compiled rules, hunts, and response guidance.
- Disable stops future evaluation and recommendations while preserving detections, feedback, incidents, and journal history.
- Uninstall removes pack registration metadata only; historical evidence remains durable.

Shared safety guarantees:

- Core rules `R001-R544` stay immutable.
- Pack rules use prefixed IDs and are validated against collisions.
- Mandatory journaling cannot be disabled.
- Destructive response actions cannot be automatic.
- Benchmarks and replay samples can be used before promoting a pack to paging alert modes.
