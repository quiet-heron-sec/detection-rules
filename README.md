# detection-rules

Sigma and YARA rules written from malware campaigns analysed by quiet-heron-sec. Each campaign has its own folder with a short description of the activity, the rules and the reference samples they were tested against.

## Campaigns

| Folder | Activity | Sigma | YARA |
|---|---|---|---|
| [`campaigns/2026-11-fake-plugin-catalogues`](campaigns/2026-11-fake-plugin-catalogues/) | fake software plugin catalogues distributing loaders, a remote access implant and stealer payloads (October to November 2026) | 8 | 12 |

## Testing

Sigma rules pass `sigma check` and are replayed with Chainsaw on Sysmon logs, from a clean Windows 11 host and from a host that reproduces the observed behaviour. YARA rules are checked with YARA-X, the CCCS YARA validator and yaraQA, against their reference samples and a corpus of clean files. Rules start as `experimental` (Sigma) or `TESTING` (YARA) until they have been run in production.

## Licences

Sigma rules: Detection Rule License 1.1 ([`LICENSE-sigma-DRL-1.1.md`](LICENSE-sigma-DRL-1.1.md)). YARA rules: Creative Commons Attribution 4.0 ([`LICENSE-yara-CC-BY-4.0.txt`](LICENSE-yara-CC-BY-4.0.txt)).
