@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Privesc.psm1'

# Version number of this module.
ModuleVersion = '3.0.0.0'

# ID used to uniquely identify this module
GUID = 'efb2a78f-a069-4bfd-91c2-7c7c0c225f56'

# Author of this module
Author = 'Will Schroder'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Privesc Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @(  
    'Find-DLLHijack',
    'Find-PathHijack',
    'Get-ApplicationHost',
    'Get-RegAlwaysInstallElevated',
    'Get-RegAutoLogon',
    'Get-ServiceDetail',
    'Get-ServiceFilePermission',
    'Get-ServicePermission',
    'Get-ServiceUnquoted',
    'Get-UnattendedInstallFile',
    'Get-VulnAutoRun',
    'Get-VulnSchTask',
    'Get-Webconfig',
    'Install-ServiceBinary',
    'Invoke-AllChecks',
    'Invoke-ServiceAbuse',
    'Restore-ServiceBinary',
    'Write-HijackDll',
    'Write-ServiceBinary',
    'Write-UserAddMSI',
    'Get-SiteListPassword'
)

# List of all files packaged with this module
FileList = 'Privesc.psm1', 'PowerUp.ps1', 'README.md'

}

