# Fake plugin catalogues (August to November 2026)

Sigma, YARA and Suricata rules for a fake plugin catalogue campaign. Activity has been observed since 2026-08-31 on a ClickFix server of the PluginDex branch, and the catalogues were online in October and November 2026. At least two branches distribute malware through sites posing as software plugin catalogues:

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
| `registry_set_win_run_key_hhunter_reserve_names.yml` | registry_set | high |
| `registry_set_win_hkcu_software_random_key_base64_value.yml` | registry_set | medium |
| `registry_set_win_hkcu_software_random_key_base64_value_explorer.yml` | registry_set | high |

The last five rules target the RuntimeBroker payload (dropped by `Plugin_Setup_4.6.5.zip`, shipped alone in `Plugin_Setup_4.6.8.zip`): a Defender exclusion added by PowerShell for the fake `C:\ProgramData\Windows\Microsoft` folder, any process started from `C:\ProgramData\Windows\`, `gpupdate /force` run by `cmd.exe` from an unusual parent location, the module cache the payload writes under `HKCU\Software\WinRAR\Libs`, and any network connection by an executable under `C:\ProgramData\` that carries a Windows system binary name. The WinGup rule does not match `4.6.8`: there is no WinGup, and dynamic triage shows `powershell.exe` started by `cmd.exe`, itself started by `RuntimeBroker.exe`.

All rules pass `sigma check` (sigma-cli 4.0.0, pySigma 2.0.2). Test conditions:

- host: Windows 11 Pro 26H2 (build 10.0.26300), English, restored from a clean snapshot before each run
- logging: Sysmon 15.22, Security event log
- replay: Chainsaw 2.17.1 on the exported EVTX files
- clean run: no detection from any rule during the idle periods on the clean snapshot
- positive run: each rule fires on a reproduction of the observed behaviour, using renamed copies of legitimate binaries for the process rules (no malware executed). The EventSystem and WinRAR Libs rules need the added `RegistryEvent` include lines listed below
- the EventSystem rule fires only when the Sysmon configuration logs registry writes under `\Software\Microsoft\EventSystem\` (one added `RegistryEvent` include line), and the WinRAR Libs rule only when it logs `\Software\WinRAR\Libs`
- the four process_creation and registry_set rules added for the RuntimeBroker payload were tested on 2026-11-08 with signed Windows binaries copied or renamed under `C:\ProgramData\`, a real Defender exclusion added then removed, and a real `gpupdate /force`. All 9 expected detections fired: 2 for the Defender exclusion, 2 for execution from the fake folder, 3 for gpupdate and 2 for the WinRAR Libs key. A ten-minute idle run, the negative cases (the genuine `C:\ProgramData\Microsoft\Windows` folder, a `System32` parent, `Remove-MpPreference`) and a session with WinRAR 7.23, which did not write the `Libs` key, produced no detection
- the network rule does not filter on `Initiated`: with `Initiated: 'true'`, Chainsaw 2.17.1 read the field as a boolean and returned nothing. On 2026-11-08 the published file was replayed unchanged with Chainsaw 2.17.1 and Zircolite 4.7.1 (`-p sysmon`), and with Hayabusa 4.3.1 on a copy that adds `Channel: Microsoft-Windows-Sysmon/Operational` and `EventID: 3`, without which Hayabusa disables the rule: 4 detections on each engine (three outbound connections and one received by the fake system binary), none on the negative case. No SIEM was tested

The `OriginalFileName` criteria are not covered by the positive run: a renamed copy keeps the `OriginalFileName` of the binary it was copied from.

The last three rules target the reserve backdoor of the hhunter implant, read from its code. The server enables it with a flag, and neither write has been observed on an infected host. They were tested on 2026-11-09 on Windows 11 with Sysmon 15.22, using harmless `reg add` writes (no sample, no `deno.exe` on the host), with sigma-cli 4.0.0 (SQLite backend), Chainsaw 2.17.1, Hayabusa 4.3.1 and Zircolite 4.7.1. All four tools returned identical counts:

- Run key rule: 14 detections out of 14 expected (the 12 names of the implant's reserve table with `deno` in the value data, one name whose value data starts a hidden `conhost --headless` registry reader, and one name under HKLM), no detection on ordinary names, longer names, other value data or `RunOnce`
- HKCU key rule: 4 detections out of 4 expected (base64 data of 100, 200 and 6,000 characters, and the same write typed as `HKCU\SOFTWARE`, which Sysmon logs as `\Software\`), no detection on boundary lengths (key or value name one character too short or too long), an upper-case key name, shorter base64, plain text, `REG_BINARY` or a deeper key. It fires only on Sysmon event ID 13 (registry value set) logged under `HKU\<SID>\Software`: with a Sysmon configuration that does not monitor those keys, the same writes produced no event at all
- false positives: no detection on the events outside the test plan (61,718 registry events), and none in a user hive of 6,605 values. The test profile was nearly fresh, so this says little about a used workstation
- Explorer variant of the HKCU key rule: same detection, restricted to writes by `explorer.exe`, for hosts whose Sysmon configuration does not log `HKU\<SID>\Software` broadly. It needs this added rule group, tested on 2026-11-09 with Sysmon 15.22 alone and merged into a common configuration:

```xml
<RuleGroup name="explorer_hkcu_software" groupRelation="and">
  <RegistryEvent onmatch="include">
    <Image condition="image">explorer.exe</Image>
    <EventType condition="is">SetValue</EventType>
    <TargetObject condition="excludes any">\Software\Microsoft\;\Software\Classes\;\Software\Policies\;\Software\Wow6432Node\;_Classes\</TargetObject>
  </RegistryEvent>
</RuleGroup>
```

  With this group, Sysmon logged the 5 expected writes of 13 test cases and none of the 8 to exclude, real Explorer writes outside the excluded subtrees (`Control Panel\NotifyIconSettings`), and no event during a scripted session of about three minutes, where a control run logging the whole registry recorded about 3,100 Explorer events per minute. The same group with `excludes all` did not filter. The test used a renamed copy of `reg.exe` and checks the logging only: no real write by Explorer in the format of the key has been observed, and the rule stays `experimental`

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

`MAL_RAT_HHunter_Nov26` version 1.1 adds a second branch: 8 of the 10 reserve table names that appear in clear text, plus the `reserve_enabled` JSON field. The reference sample matches the full rule and the second branch alone, and neither matches the clean corpus. A build that changes those names evades only the second branch, the first one still applies. `MAL_RAT_HHunter_Memory_Nov26` is unchanged.

Each rule matches its reference sample and was checked with YARA-X, the CCCS YARA validator and yaraQA. All files compile with YARA 4.2.3.

False positive test: 21,937 clean files (12,449 of them PE), none matched. The corpus contains the files extracted from the `install.wim` of an official Windows 11 ISO, the official WinGup package (with its genuine `libcurl.dll`) and the Notepad++ 8.9.9 package.

## Suricata

`suricata/fake-plugin-catalogues.rules` holds 46 rules for Suricata 7 (SID 9100001 to 9100135):

| Group | SID | Content |
|---|---|---|
| RuntimeBroker payload | 9100001, 9100002 | 9100001: clear-text WebSocket handshake using the RFC 6455 example key to TCP port 406. 9100002 (hunting): the same key on any port. The pattern comes from emulating the payload |
| hhunter VNC tunnel | 9100003 | TLS certificate `CN=hhunter-vnc`, TLS 1.2 only |
| ClickFix | 9100004, 9100005 | 9100004: kit download URL. 9100005 (hunting): PowerShell downloading a `.ps1` |
| Archive download | 9100006, 9100007 | malicious archive and `/go/` page, visible only with TLS inspection |
| Servers | 9100010 to 9100012 | known command and download servers, short-lived: remove them once the servers are taken down |
| Domains | 9100100 to 9100135 | 12 domains in DNS queries and TLS SNI, and in the HTTP Host header for networks where DNS is not visible (external resolver, DoH) |

Tested on 2026-11-09 with Suricata 7.0.10 (Debian package, default configuration) in an isolated network, on crafted harmless traffic, clear-text HTTP included for the archive rules: 122 cases, every SID fired at least once and no rule fired on its negative cases. `suricata -T` reported no warning. Ten minutes of scripted clean traffic (16,051 packets) raised no alert. Limits:

- 9100003 does not fire on TLS 1.3 or on a resumed TLS 1.2 session
- Suricata 7 does not inspect WebSocket frames after the 101 response, so the rest of the TCP 406 flow is not covered
- the server rules were tested on crafted captures only, and the clean traffic run is too short to stand for an enterprise network
- the archive rules fire on production HTTPS traffic only where TLS is inspected
- no check for content overlap with Emerging Threats rules (the PowerShell `.ps1` pattern is generic)

## Licences

See the [root README](../../README.md#licences).
