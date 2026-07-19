rule Android_Suspicious_Dynamic_Loading {
    meta:
        description = "Detects suspicious dynamic code loading patterns in Android apps"
        author = "AegisDroid"
        severity = "high"
        category = "dynamic_code"
    strings:
        $dex1 = "DexClassLoader" ascii
        $dex2 = "PathClassLoader" ascii
        $dex3 = "InMemoryDexClassLoader" ascii
        $dex4 = "DexFile" ascii
        $reflect1 = "Class.forName" ascii
        $reflect2 = "getMethod" ascii
        $reflect3 = "invoke" ascii
        $dalvik = "dalvik/system" ascii
    condition:
        2 of ($dex*) or (1 of ($dex*) and 1 of ($reflect*)) or $dalvik
}

rule Android_Debug_Build {
    meta:
        description = "Detects Android debug build artifacts"
        author = "AegisDroid"
        severity = "medium"
        category = "build_anomaly"
    strings:
        $debug1 = "android:debuggable=\"true\"" ascii
        $debug2 = "Debug build" ascii
        $debug3 = "test-keys" ascii
        $debug4 = "ro.debuggable=1" ascii
    condition:
        any of them
}

rule Android_Suspicious_Permissions {
    meta:
        description = "App requests multiple high-risk permissions simultaneously"
        author = "AegisDroid"
        severity = "high"
        category = "permission_anomaly"
    strings:
        $p1 = "SEND_SMS" ascii
        $p2 = "RECORD_AUDIO" ascii
        $p3 = "CAMERA" ascii
        $p4 = "ACCESS_FINE_LOCATION" ascii
        $p5 = "READ_CONTACTS" ascii
        $p6 = "READ_SMS" ascii
        $p7 = "PROCESS_OUTGOING_CALLS" ascii
        $p8 = "WRITE_CALL_LOG" ascii
        $p9 = "BIND_ACCESSIBILITY_SERVICE" ascii
    condition:
        4 of them
}

rule Android_Root_Toolkit {
    meta:
        description = "Detects Android root toolkit artifacts"
        author = "AegisDroid"
        severity = "critical"
        category = "root"
    strings:
        $magisk = "magisk" ascii nocase
        $supersu = "SuperSU" ascii
        $superuser = "Superuser" ascii
        $busybox = "busybox" ascii
        $ksu = "KernelSU" ascii
        $apatch = "APatch" ascii
    condition:
        any of them
}

rule Android_Suspicious_URLs {
    meta:
        description = "Detects suspicious URLs embedded in Android apps"
        author = "AegisDroid"
        severity = "medium"
        category = "network_anomaly"
    strings:
        $url1 = /https?:\/\/[^\s]+\.(tk|ml|ga|cf|gq|xyz|top|buzz)\/[^\s]{5,}/ ascii
        $url2 = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ascii
        $url3 = "ftp://" ascii
        $ip = /([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{2,5}/ ascii
    condition:
        any of them
}

rule Android_Frida_Detector {
    meta:
        description = "Detects Frida dynamic instrumentation framework"
        author = "AegisDroid"
        severity = "high"
        category = "hooking_framework"
    strings:
        $frida1 = "frida" ascii nocase
        $frida2 = "frida-server" ascii
        $frida3 = "re.frida.server" ascii
        $frida4 = "gum-js-loop" ascii
        $frida5 = "g_main_loop" ascii
        $gadget = "libfrida-gadget.so" ascii
    condition:
        2 of them or $gadget
}

rule Android_Crypto_Miner {
    meta:
        description = "Detects cryptocurrency mining indicators"
        author = "AegisDroid"
        severity = "critical"
        category = "crypto_mining"
    strings:
        $miner1 = "stratum+tcp://" ascii
        $miner2 = "stratum+ssl://" ascii
        $miner3 = "cryptonight" ascii nocase
        $miner4 = "coinhive" ascii nocase
        $miner5 = "minergate" ascii nocase
        $miner6 = "nicehash" ascii nocase
        $miner7 = "xmrig" ascii nocase
    condition:
        any of them
}
