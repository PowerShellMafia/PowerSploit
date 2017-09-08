@{

# Script module or binary module file associated with this manifest.
ModuleToProcess = 'Recon.psm1'

# Version number of this module.
ModuleVersion = '3.0.0.0'

# ID used to uniquely identify this module
GUID = '7e775ad6-cd3d-4a93-b788-da067274c877'

# Author of this module
Author = 'Matthew Graeber', 'Will Schroeder'

# Copyright statement for this module
Copyright = 'BSD 3-Clause'

# Description of the functionality provided by this module
Description = 'PowerSploit Reconnaissance Module'

# Minimum version of the Windows PowerShell engine required by this module
PowerShellVersion = '2.0'

# Functions to export from this module
FunctionsToExport = @(
    'Export-PowerViewCSV',
    'Resolve-IPAddress',
    'ConvertTo-SID',
    'ConvertFrom-SID',
    'Convert-ADName',
    'ConvertFrom-UACValue',
    'Add-RemoteConnection',
    'Remove-RemoteConnection',
    'Invoke-UserImpersonation',
    'Invoke-RevertToSelf',
    'Get-DomainSPNTicket',
    'Invoke-Kerberoast',
    'Get-PathAcl',
    'Get-DomainDNSZone',
    'Get-DomainDNSRecord',
    'Get-Domain',
    'Get-DomainController',
    'Get-Forest',
    'Get-ForestDomain',
    'Get-ForestGlobalCatalog',
    'Find-DomainObjectPropertyOutlier',
    'Get-DomainUser',
    'New-DomainUser',
    'Set-DomainUserPassword',
    'Get-DomainUserEvent',
    'Get-DomainComputer',
    'Get-DomainObject',
    'Set-DomainObject',
    'Set-DomainObjectOwner',
    'Get-DomainObjectAcl',
    'Add-DomainObjectAcl',
    'Find-InterestingDomainAcl',
    'Get-DomainOU',
    'Get-DomainSite',
    'Get-DomainSubnet',
    'Get-DomainSID',
    'Get-DomainGroup',
    'New-DomainGroup',
    'Get-DomainManagedSecurityGroup',
    'Get-DomainGroupMember',
    'Add-DomainGroupMember',
    'Get-DomainFileServer',
    'Get-DomainDFSShare',
    'Get-DomainGPO',
    'Get-DomainGPOLocalGroup',
    'Get-DomainGPOUserLocalGroupMapping',
    'Get-DomainGPOComputerLocalGroupMapping',
    'Get-DomainPolicy',
    'Get-NetLocalGroup',
    'Get-NetLocalGroupMember',
    'Get-NetShare',
    'Get-NetLoggedon',
    'Get-NetSession',
    'Get-RegLoggedOn',
    'Get-NetRDPSession',
    'Test-AdminAccess',
    'Get-NetComputerSiteName',
    'Get-WMIRegProxy',
    'Get-WMIRegLastLoggedOn',
    'Get-WMIRegCachedRDPConnection',
    'Get-WMIRegMountedDrive',
    'Get-WMIProcess',
    'Find-InterestingFile',
    'Find-DomainUserLocation',
    'Find-DomainProcess',
    'Find-DomainUserEvent',
    'Find-DomainShare',
    'Find-InterestingDomainShareFile',
    'Find-LocalAdminAccess',
    'Find-DomainLocalGroupMember',
    'Get-DomainTrust',
    'Get-ForestTrust',
    'Get-DomainForeignUser',
    'Get-DomainForeignGroupMember',
    'Get-DomainTrustMapping',
    'Get-ComputerDetail',
    'Get-HttpStatus',
    'Invoke-Portscan',
    'Invoke-ReverseDnsLookup'
)

# List of all files packaged with this module
FileList = 'Recon.psm1', 'Recon.psd1', 'PowerView.ps1', 'Get-HttpStatus.ps1', 'Invoke-ReverseDnsLookup.ps1',
               'Invoke-Portscan.ps1', 'Get-ComputerDetails.ps1', 'README.md'

}
