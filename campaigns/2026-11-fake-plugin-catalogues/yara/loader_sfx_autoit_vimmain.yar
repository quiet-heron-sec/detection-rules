import "pe"

rule MAL_Loader_SFX_AutoIt_VimMain_Nov26 {
    meta:
        id = "3A86keLezQFPO2dsZIphrf"
        fingerprint = "6eede80379dfd5c75eb973bb818883900b5c91f9320d68d73695640f1c5cd394"
        version = "1.0"
        score = 80
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects a 7-Zip SFX DLL exporting VimMain that runs AutoIt3.exe, side-loaded by a signed gVim"
        category = "MALWARE"
        malware = "AUTOIT SFX LOADER"
        malware_type = "LOADER"
        mitre_att = "T1574.001"
        reference = "https://bazaar.abuse.ch/sample/40e9906f017d9285fcd3ef01d5d87d56784350189734ba78f4260227dbe73b2d/"
        hash = "40e9906f017d9285fcd3ef01d5d87d56784350189734ba78f4260227dbe73b2d"
        yarahub_reference_md5 = "76b8b78a5596046815a4664d0605594c"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/loader_sfx_autoit_vimmain.yar"
        yarahub_uuid = "911aa7ce-2c43-41b2-a53a-e6c262c951f0"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $cfg_begin = ";!@Install@!UTF-8!" ascii
        $cfg_end = ";!@InstallEnd@!" ascii
        $cfg_run = "RunProgram=\"AutoIt3.exe " ascii
        $cfg_hidden = "GUIMode=\"2\"" ascii
        $magic_7z = { 37 7A BC AF 27 1C }

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and pe.is_dll()
        and pe.exports("VimMain")
        and pe.overlay.size > 0
        and $cfg_begin in (pe.overlay.offset .. pe.overlay.offset + 1024)
        and $cfg_run in (pe.overlay.offset .. pe.overlay.offset + 1024)
        and $magic_7z in (pe.overlay.offset .. pe.overlay.offset + 2048)
        and all of ($cfg_end, $cfg_hidden)
}

rule MAL_Loader_SFX_AutoIt_Vim64_Build_Nov26 {
    meta:
        id = "4b5y6WbpoolfyGCJYlLkPj"
        fingerprint = "0ca41ef45bc70c204ff7ca925588cfc6e2e53de0cb7175ee29b39d99fef5a02a"
        version = "1.0"
        score = 90
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects the vim64.dll build of a 7-Zip SFX AutoIt loader seen in the wild in November 2026"
        category = "MALWARE"
        malware = "AUTOIT SFX LOADER"
        malware_type = "LOADER"
        mitre_att = "T1574.001"
        reference = "https://bazaar.abuse.ch/sample/40e9906f017d9285fcd3ef01d5d87d56784350189734ba78f4260227dbe73b2d/"
        hash = "40e9906f017d9285fcd3ef01d5d87d56784350189734ba78f4260227dbe73b2d"
        yarahub_reference_md5 = "76b8b78a5596046815a4664d0605594c"
        yarahub_reference_link = "https://github.com/quiet-heron-sec/detection-rules/blob/main/campaigns/2026-11-fake-plugin-catalogues/yara/loader_sfx_autoit_vimmain.yar"
        yarahub_uuid = "fc8d7833-f708-48d6-8515-97d5a91b0861"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    condition:
        uint16(0) == 0x5A4D
        and filesize < 20MB
        and pe.is_dll()
        and pe.exports("VimMain")
        and pe.sections[0].name == ".agendax"
        and pe.sections[1].name == ".rarelyx"
        and pe.sections[10].name == ".yoursxx"
        and pe.exports("?ParOrchestraSteal@@YAXXZ")
        and pe.exports("?TransmissionUniprotkbOpportunity@@YAXXZ")
}
