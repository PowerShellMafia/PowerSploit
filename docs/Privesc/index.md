## PowerUp

PowerUp aims to be a clearinghouse of common Windows privilege escalation
vectors that rely on misconfigurations.

Running Invoke-AllChecks will output any identifiable vulnerabilities along
with specifications for any abuse functions. The -HTMLReport flag will also
generate a COMPUTER.username.html version of the report.

Author: @harmj0y
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None


### Token/Privilege Enumeration/Abuse:
    Get-ProcessTokenGroup               -   returns all SIDs that the current token context is a part of, whether they are disabled or not
    Get-ProcessTokenPrivilege           -   returns all privileges for the current (or specified) process ID
    Enable-Privilege                    -   enables a specific privilege for the current process

### Service Enumeration/Abuse:
    Test-ServiceDaclPermission          -   tests one or more passed services or service names against a given permission set
    Get-UnquotedService                 -   returns services with unquoted paths that also have a space in the name
    Get-ModifiableServiceFile           -   returns services where the current user can write to the service binary path or its config
    Get-ModifiableService               -   returns services the current user can modify
    Get-ServiceDetail                   -   returns detailed information about a specified service
    Set-ServiceBinaryPath               -   sets the binary path for a service to a specified value
    Invoke-ServiceAbuse                 -   modifies a vulnerable service to create a local admin or execute a custom command
    Write-ServiceBinary                 -   writes out a patched C# service binary that adds a local admin or executes a custom command
    Install-ServiceBinary               -   replaces a service binary with one that adds a local admin or executes a custom command
    Restore-ServiceBinary               -   restores a replaced service binary with the original executable

### DLL Hijacking:
    Find-ProcessDLLHijack               -   finds potential DLL hijacking opportunities for currently running processes
    Find-PathDLLHijack                  -   finds service %PATH% DLL hijacking opportunities
    Write-HijackDll                     -   writes out a hijackable DLL
    
### Registry Checks:
    Get-RegistryAlwaysInstallElevated   -   checks if the AlwaysInstallElevated registry key is set
    Get-RegistryAutoLogon               -   checks for Autologon credentials in the registry
    Get-ModifiableRegistryAutoRun       -   checks for any modifiable binaries/scripts (or their configs) in HKLM autoruns

### Miscellaneous Checks:
    Get-ModifiableScheduledTaskFile     -   find schtasks with modifiable target files
    Get-UnattendedInstallFile           -   finds remaining unattended installation files
    Get-Webconfig                       -   checks for any encrypted web.config strings
    Get-ApplicationHost                 -   checks for encrypted application pool and virtual directory passwords
    Get-SiteListPassword                -   retrieves the plaintext passwords for any found McAfee's SiteList.xml files
    Get-CachedGPPPassword               -   checks for passwords in cached Group Policy Preferences files

### Other Helpers/Meta-Functions:
    Get-ModifiablePath                  -   tokenizes an input string and returns the files in it the current user can modify
    Write-UserAddMSI                    -   write out a MSI installer that prompts for a user to be added
    Invoke-WScriptUACBypass             -   performs the bypass UAC attack by abusing the lack of an embedded manifest in wscript.exe
    Invoke-PrivescAudit                 -   runs all current escalation checks and returns a report (formerly Invoke-AllChecks)
