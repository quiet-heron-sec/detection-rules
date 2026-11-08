import "pe"

rule MAL_Backdoor_RuntimeBroker_WebSocket_Nov26 {
    meta:
        id = "7Zksjuar74DG34Blf4Zhj1"
        fingerprint = "7b8d49cf3316116b85da0288b6203dbf024b275f1ab4682324ef1c4e5f3e6a78"
        version = "1.0"
        score = 75
        minimum_yara = "4.2"
        date = "2026-11-08"
        modified = "2026-11-08"
        status = "TESTING"
        sharing = "TLP:CLEAR"
        source = "QUIET-HERON-SEC"
        author = "quiet-heron-sec"
        description = "Detects a backdoor that installs itself as RuntimeBroker.exe in ProgramData and uses a WebSocket C2"
        category = "MALWARE"
        malware = "RUNTIMEBROKER WEBSOCKET BACKDOOR"
        malware_type = "BACKDOOR"
        mitre_att = "T1036.005"
        reference = "https://bazaar.abuse.ch/sample/40ea2317b6703a8b3e0108ed49686203cdafc59c59ff8c604bd46740c405e5a5/"
        hash = "40ea2317b6703a8b3e0108ed49686203cdafc59c59ff8c604bd46740c405e5a5"
        yarahub_reference_md5 = "c9cca2f963fac36be7252222c960db53"
        yarahub_uuid = "93890fe7-24e3-43f5-9048-1829b41313a2"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"

    strings:
        $chunk1 = "%s_%s_chunk_%d" ascii
        $chunk2 = "%s_%s_tempchunk_%d" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 5MB
        and pe.is_64bit()
        and for any s in pe.sections : ( s.name == ".strenc" )
        and pe.imports("KERNEL32.dll", "GetVolumeInformationA")
        and pe.imports("KERNEL32.dll", "WriteProcessMemory")
        and pe.imports("KERNEL32.dll", "CreateMutexA")
        and all of ($chunk*)
}
