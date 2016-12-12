@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Privesc.psm1'

# Version number of this module.
ModuleVersion = '3.0.0.0'

# ID used to uniquely identify this module
GUID = 'efb2a78f-a069-4bfd-91c2-7c7c0c225f56'

# Author of this module
Author = 'Will Schroeder'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Privesc Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @(
    'Add-ServiceDacl',
    'Find-PathDLLHijack',
    'Find-ProcessDLLHijack',
    'Get-ApplicationHost',
    'Get-CachedGPPPassword',
    'Get-CurrentUserTokenGroupSid',
    'Get-ModifiablePath',
    'Get-ModifiableRegistryAutoRun',
    'Get-ModifiableScheduledTaskFile',
    'Get-ModifiableService',
    'Get-ModifiableServiceFile',
    'Get-RegistryAlwaysInstallElevated',
    'Get-RegistryAutoLogon',
    'Get-ServiceDetail',
    'Get-ServiceUnquoted',
    'Get-SiteListPassword',
    'Get-System',
    'Get-UnattendedInstallFile',
    'Get-Webconfig',
    'Install-ServiceBinary',
    'Invoke-AllChecks',
    'Invoke-ServiceAbuse',
    'Restore-ServiceBinary',
    'Set-ServiceBinPath',
    'Test-ServiceDaclPermission',
    'Write-HijackDll',
    'Write-ServiceBinary',
    'Write-UserAddMSI'
)

# List of all files packaged with this module
FileList = 'Privesc.psm1', 'Get-System.ps1', 'PowerUp.ps1', 'README.md'

}

