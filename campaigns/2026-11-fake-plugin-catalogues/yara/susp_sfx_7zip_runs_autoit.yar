rule SUSP_SFX_7Zip_Runs_AutoIt_Nov26 {
    meta:
        id = "3ekpiZc7WWc18IiUTsLqNU"
        fingerprint = "90036637e72410a800f12570fddd60bf06eaacb47d366dfc8a666428a1980e99"
        version = "1.0"
        score = 60
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects a PE carrying a 7-Zip SFX configuration that runs the AutoIt3 interpreter, a common pattern of AutoIt malware loaders"
        category = "TECHNIQUE"
        technique = "LOADER"
        mitre_att = "T1059.010"
        reference = "https://bazaar.abuse.ch/sample/40e9906f017d9285fcd3ef01d5d87d56784350189734ba78f4260227dbe73b2d/"
        hash = "40e9906f017d9285fcd3ef01d5d87d56784350189734ba78f4260227dbe73b2d"
        yarahub_reference_md5 = "76b8b78a5596046815a4664d0605594c"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/susp_sfx_7zip_runs_autoit.yar"
        yarahub_uuid = "b45782f9-bb0b-4d06-b0d9-660a6864bf6e"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $cfg = ";!@Install@!UTF-8!" ascii
        $run1 = "RunProgram=\"AutoIt3.exe" ascii nocase
        $run2 = "RunProgram=\"AutoIt3_x64.exe" ascii nocase
        $run3 = "ExecuteFile=\"AutoIt3.exe" ascii nocase
        $run4 = "ExecuteFile=\"AutoIt3_x64.exe" ascii nocase

    condition:
        uint16(0) == 0x5A4D
        and filesize < 50MB
        and $cfg
        and 1 of ($run*)
}
