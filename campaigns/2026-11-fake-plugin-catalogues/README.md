# Fake plugin catalogues (October to November 2026)

Sigma and YARA rules for a fake plugin catalogue campaign active in October and November 2026. Two branches distribute malware through sites posing as software plugin catalogues:

- **PluginDex** (plugin-dex[.]com, plugin-dex[.]cc, plugin-dex[.]forum, wppluginindex[.]com): a ClickFix chain that relies on Deno and installs a remote access implant, and a later archive in which a signed WinGup updater side-loads a trojanized `libcurl.dll`.
- **AnyPlugins** (anyplugins[.]com): a signed gVim build side-loads a trojanized `vim64.dll`, a 7-Zip SFX module that runs a compiled AutoIt script, which decrypts a payload and injects it by process hollowing.

Both branches use a signed legitimate executable that loads a trojanized DLL placed next to it. This shared technique does not establish a common operator.

## Sigma

| Rule | Log source | Level |
|---|---|---|
| `proc_creation_win_autoit3_spawned_by_gvim.yml` | process_creation | high |
| `proc_creation_win_autoit3_spawns_autoit3_no_args.yml` | process_creation | high |
| `proc_creation_win_autoit3_spawns_chrome.yml` | process_creation | high |
| `proc_creation_win_deno_eval_atob.yml` | process_creation | high |
| `proc_creation_win_runtimebroker_in_programdata.yml` | process_creation | high |
| `proc_creation_win_wingup_spawns_defender_exclusion.yml` | process_creation | high |
| `registry_set_win_eventsystem_system_value.yml` | registry_set | medium |
| `registry_set_win_run_key_deno_eval.yml` | registry_set | high |

All rules pass `sigma check` (sigma-cli 4.0.0, pySigma 2.0.2). They were replayed with Chainsaw on Sysmon logs from a clean Windows 11 host (no false positive) and from a host that reproduces the observed behaviour (expected detections).

## YARA

| File | Rules | Reference sample |
|---|---|---|
| `backdoor_runtimebroker_websocket.yar` | 1 | MalwareBazaar 40ea2317 |
| `loader_autoit_a3x_padded.yar` | 2 | MalwareBazaar 3592f41d |
| `loader_sfx_autoit_vimmain.yar` | 2 | MalwareBazaar 40e9906f |
| `loader_wingup_libcurl_sideload.yar` | 2 | VirusTotal 22dadd30 |
| `rat_hhunter.yar` | 2 (file and memory) | MalwareBazaar 5410f0b6 |
| `stealer_payload_indirect_call.yar` | 2 | MalwareBazaar 27eab923 |
| `susp_sfx_7zip_runs_autoit.yar` | 1 (generic) | MalwareBazaar 40e9906f |

Each rule matches its reference sample and was checked with YARA-X, the CCCS YARA validator and yaraQA. No match on 21 937 files of a clean corpus (Windows 11, genuine WinGup with its `libcurl.dll`, Notepad++).

## Licences

See the [root README](../../README.md#licences).
