"""Registry path configuration for monitoring targets."""

REGISTRY_PATHS = {
    "autorun_keys": [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    ],
    "security_keys": {
        "windows_defender": [
            r"HKLM\SOFTWARE\Policies\Microsoft\Windows Defender",
            r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
        ],
        "firewall": [
            (
                r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
                r"\FirewallPolicy\DomainProfile"
            ),
            (
                r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters"
                r"\FirewallPolicy\StandardProfile"
            ),
        ],
        "uac": [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        ],
    },
    "system_behavior_keys": {
        "shell_replacements": [
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        ],
        "startup_behavior": [
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        ],
    },
}
