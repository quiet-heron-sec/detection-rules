# Fake plugin catalogues (August to November 2026)

Sigma and YARA rules for a fake plugin catalogue campaign. Activity is observed from 2026-08-31, on a ClickFix server of the PluginDex branch, and the catalogues are online in October and November 2026. At least two branches distribute malware through sites posing as software plugin catalogues:

- **PluginDex** (plugin-dex[.]com, plugin-dex[.]cc, plugin-dex[.]forum, wppluginindex[.]com): fake installers and cracks that start a Deno loader, which injects an implant into Explorer (hidden desktop, browser and Telegram data theft), a ClickFix chain (`svvv2.ps1`, then an MSI installer), and a later archive in which a signed WinGup updater side-loads a trojanized `libcurl.dll`.
- **AnyPlugins** (anyplugins[.]com): a signed gVim build side-loads a trojanized `vim64.dll`, a 7-Zip SFX module that runs a compiled AutoIt script, which decrypts a payload and injects it by process hollowing.

In each branch, at least one archive uses a signed legitimate executable that loads a trojanized DLL placed next to it (gVim and `vim64.dll` for AnyPlugins, WinGup and `libcurl.dll` in PluginDex's `Plugin_Setup_4.6.5.zip`). This shared technique does not necessarily mean a common actor is involved.

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

All rules pass `sigma check` (sigma-cli 4.0.0, pySigma 2.0.2). Test conditions:

- host: Windows 11 Pro 26H2 (build 10.0.26300), English, restored from a clean snapshot before each run
- logging: Sysmon 15.22, Security event log
- replay: Chainsaw 2.17.1 on the exported EVTX files
- clean run: no detection from any rule
- positive run: each rule fires on a reproduction of the observed process or registry behaviour, using renamed copies of legitimate binaries (no malware executed)
- the EventSystem rule fires only once the Sysmon configuration logs registry writes under `\Software\Microsoft\EventSystem\` (one added `RegistryEvent` include line)

The `OriginalFileName` criteria are not covered by the positive run, since the copies are renamed.

## YARA

| File | Rules | Reference sample |
|---|---|---|
| `loader_autoit_a3x_padded.yar` | 2 | MalwareBazaar 3592f41d |
| `loader_sfx_autoit_vimmain.yar` | 2 | MalwareBazaar 40e9906f |
| `loader_wingup_libcurl_sideload.yar` | 2 | VirusTotal 22dadd30 |
| `payload_runtimebroker_websocket.yar` | 1 | MalwareBazaar 40ea2317 |
| `rat_hhunter.yar` | 2 (file and memory) | MalwareBazaar 5410f0b6 |
| `stealer_payload_indirect_call.yar` | 2 | MalwareBazaar 27eab923 |
| `susp_sfx_7zip_runs_autoit.yar` | 1 (generic) | MalwareBazaar 40e9906f |

Each rule matches its reference sample and was checked with YARA-X, the CCCS YARA validator and yaraQA. All files compile with YARA 4.2.3.

False positive test: 21 937 clean files, 12 449 of them PE, no match. The corpus holds the files extracted from the `install.wim` of an official Windows 11 ISO, and the official WinGup (with its genuine `libcurl.dll`) and Notepad++ 8.9.9 packages.

## Licences

See the [root README](../../README.md#licences).
