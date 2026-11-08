# detection-rules

Sigma and YARA rules intended for sharing. Some rules come from the analysis of a specific campaign, others describe a technique independently of any campaign. Rules start as `experimental` (Sigma) or `TESTING` (YARA) and only change status after use in production.

## Layout

| Folder | Content |
|---|---|
| [`campaigns/`](campaigns/) | one folder per campaign, with a short description of the activity, its rules and the reference samples |

Each folder describes how its rules were tested: Sigma log sources, test host and replay tool, YARA reference samples and the size of the clean corpus used for false positives.

## Campaigns

| Folder | Activity | Sigma | YARA |
|---|---|---|---|
| [`2026-11-fake-plugin-catalogues`](campaigns/2026-11-fake-plugin-catalogues/) | fake software plugin catalogues distributing loaders, a remote access implant and stealer payloads (August to November 2026) | 8 | 12 |

## Licences

Sigma rules: Detection Rule License 1.1 ([`LICENSE-sigma-DRL-1.1.md`](LICENSE-sigma-DRL-1.1.md)). YARA rules: Creative Commons Attribution 4.0 ([`LICENSE-yara-CC-BY-4.0.txt`](LICENSE-yara-CC-BY-4.0.txt)).
