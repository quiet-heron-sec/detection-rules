# Fake plugin catalogues (August to November 2026)

Sigma and YARA rules for a fake plugin catalogue campaign. Activity has been observed since 2026-08-31 on a ClickFix server of the PluginDex branch, and the catalogues were online in October and November 2026. At least two branches distribute malware through sites posing as software plugin catalogues:

- **PluginDex** (plugin-dex[.]com, plugin-dex[.]cc, plugin-dex[.]forum, wppluginindex[.]com, pluginfolio[.]com): fake installers and cracks that start a Deno loader, which injects an implant into Explorer (hidden desktop, browser and Telegram data theft), a ClickFix chain (`svvv2.ps1`, then an MSI installer), and later archives. In `Plugin_Setup_4.6.5.zip`, a signed WinGup updater side-loads a trojanized `libcurl.dll`, which drops a payload copied as `C:\ProgramData\Windows\Microsoft\RuntimeBroker.exe`. `Plugin_Setup_4.6.8.zip` (pluginfolio[.]com, 2026-11-08) holds a new build of that payload alone, `Plugin_Installer_3.5.3.exe`, with no WinGup and no DLL.
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
| `proc_creation_win_defender_exclusion_fake_programdata_windows.yml` | process_creation | high |
| `proc_creation_win_susp_exec_from_fake_programdata_windows.yml` | process_creation | high |
| `proc_creation_win_cmd_gpupdate_force_susp_parent_location.yml` | process_creation | medium |
| `registry_set_malware_runtimebroker_loader_winrar_libs.yml` | registry_set | high |
| `net_connection_win_susp_system_exe_name_programdata.yml` | network_connection | high |

The last five rules target the RuntimeBroker payload (dropped by `Plugin_Setup_4.6.5.zip`, shipped alone in `Plugin_Setup_4.6.8.zip`): a Defender exclusion added by PowerShell for the fake `C:\ProgramData\Windows\Microsoft` folder, any process started from `C:\ProgramData\Windows\`, `gpupdate /force` run by `cmd.exe` from an unusual parent location, the module cache the payload writes under `HKCU\Software\WinRAR\Libs`, and any network connection by an executable under `C:\ProgramData\` that carries a Windows system binary name. The WinGup rule does not match `4.6.8`: there is no WinGup, and the lab triage shows `powershell.exe` started by `cmd.exe`, itself started by `RuntimeBroker.exe`.

All rules pass `sigma check` (sigma-cli 4.0.0, pySigma 2.0.2). Test conditions:

- host: Windows 11 Pro 26H2 (build 10.0.26300), English, restored from a clean snapshot before each run
- logging: Sysmon 15.22, Security event log
- replay: Chainsaw 2.17.1 on the exported EVTX files
- clean run: no detection from any rule during the idle periods on the clean snapshot
- positive run: each rule fires on a reproduction of the observed behaviour, using renamed copies of legitimate binaries for the process rules (no malware executed). The two registry rules need the added `RegistryEvent` include lines listed below
- the EventSystem rule fires only when the Sysmon configuration logs registry writes under `\Software\Microsoft\EventSystem\` (one added `RegistryEvent` include line), and the WinRAR Libs rule only when it logs `\Software\WinRAR\Libs`
- the four new process_creation and registry_set rules were tested on 2026-11-08 with signed Windows binaries copied or renamed under `C:\ProgramData\`, a real Defender exclusion added then removed, and a real `gpupdate /force`. All 9 expected detections fired: 2 for the Defender exclusion, 2 for execution from the fake folder, 3 for gpupdate and 2 for the WinRAR Libs key. A ten-minute idle run, the negative cases (the genuine `C:\ProgramData\Microsoft\Windows` folder, a `System32` parent, `Remove-MpPreference`) and a session with WinRAR 7.23, which did not write the `Libs` key, produced no detection
- the network rule does not filter on `Initiated`: with `Initiated: 'true'`, Chainsaw 2.17.1 reads the field as a boolean and returned nothing. On 2026-11-08 the published file was replayed unchanged with Chainsaw 2.17.1 and Zircolite 4.7.1 (`-p sysmon`), and with Hayabusa 4.3.1 on a copy that adds `Channel: Microsoft-Windows-Sysmon/Operational` and `EventID: 3`, without which Hayabusa disables the rule: 4 detections on each engine (three outbound connections and one received by the fake system binary), none on the negative case. No SIEM was tested

The `OriginalFileName` criteria are not covered by the positive run: a renamed copy keeps the `OriginalFileName` of the binary it was copied from.

## YARA

| File | Rules | Reference sample |
|---|---|---|
| `loader_autoit_a3x_padded.yar` | 2 | MalwareBazaar 3592f41d |
| `loader_sfx_autoit_vimmain.yar` | 2 | MalwareBazaar 40e9906f |
| `loader_wingup_libcurl_sideload.yar` | 2 | VirusTotal 22dadd30 |
| `payload_runtimebroker_websocket.yar` | 1 | MalwareBazaar 40ea2317, also matches 396dec94 (`4.6.8`) unchanged |
| `rat_hhunter.yar` | 2 (file and memory) | MalwareBazaar 5410f0b6 |
| `stealer_payload_indirect_call.yar` | 2 | MalwareBazaar 27eab923 |
| `stealer_mops_v3.yar` | 1 | MalwareBazaar 1c850a5b and 3c110de7 |
| `susp_sfx_7zip_runs_autoit.yar` | 1 (generic) | MalwareBazaar 40e9906f |

`stealer_mops_v3.yar` targets two third-party DLLs that name themselves "Mops Stealer V3" in their log header. It does not match the RuntimeBroker payload samples (40ea2317, 396dec94).

Each rule matches its reference sample and was checked with YARA-X, the CCCS YARA validator and yaraQA. All files compile with YARA 4.2.3.

False positive test: 21,937 clean files (12,449 of them PE), none matched. The corpus contains the files extracted from the `install.wim` of an official Windows 11 ISO, the official WinGup package (with its genuine `libcurl.dll`) and the Notepad++ 8.9.9 package.

## Licences

See the [root README](../../README.md#licences).
