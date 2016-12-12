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
    'Add-NetGroupUser',
    'Add-NetUser',
    'Add-ObjectAcl',
    'Convert-NameToSid',
    'Convert-SidToName',
    'Convert-ADName',
    'ConvertFrom-UACValue',
    'Export-PowerViewCSV',
    'Find-ComputerField',
    'Find-ForeignGroup',
    'Find-ForeignUser',
    'Find-GPOComputerAdmin',
    'Find-GPOLocation',
    'Find-InterestingFile',
    'Find-LocalAdminAccess',
    'Find-ManagedSecurityGroups',
    'Find-UserField',
    'Get-ADObject',
    'Get-CachedRDPConnection',
    'Get-ComputerDetails',
    'Get-ComputerProperty',
    'Get-DFSshare',
    'Get-DNSRecord',
    'Get-DNSZone',
    'Get-DomainPolicy',
    'Get-DomainSID',
    'Get-ExploitableSystem',
    'Get-GUIDMap',
    'Get-HttpStatus',
    'Get-IPAddress',
    'Get-LastLoggedOn',
    'Get-LoggedOnLocal',
    'Get-NetComputer',
    'Get-NetDomain',
    'Get-NetDomainController',
    'Get-NetDomainTrust',
    'Get-NetFileServer',
    'Get-NetForest',
    'Get-NetForestCatalog',
    'Get-NetForestDomain',
    'Get-NetForestTrust',
    'Get-NetGPO',
    'Get-NetGPOGroup',
    'Get-NetGroup',
    'Get-NetGroupMember',
    'Get-NetLocalGroup',
    'Get-NetLoggedon',
    'Get-NetOU',
    'Get-NetProcess',
    'Get-NetRDPSession',
    'Get-NetSession',
    'Get-NetShare',
    'Get-NetSite',
    'Get-NetSubnet',
    'Get-NetUser',
    'Get-ObjectAcl',
    'Get-PathAcl',
    'Get-Proxy',
    'Get-RegistryMountedDrive',
    'Get-SiteName',
    'Get-UserEvent',
    'Get-UserProperty',
    'Invoke-ACLScanner',
    'Invoke-CheckLocalAdminAccess',
    'Invoke-DowngradeAccount',
    'Invoke-EnumerateLocalAdmin',
    'Invoke-EventHunter',
    'Invoke-FileFinder',
    'Invoke-MapDomainTrust',
    'Invoke-Portscan',
    'Invoke-ProcessHunter',
    'Invoke-ReverseDnsLookup',
    'Invoke-ShareFinder',
    'Invoke-UserHunter',
    'New-GPOImmediateTask',
    'Request-SPNTicket',
    'Set-ADObject'
)

# List of all files packaged with this module
FileList = 'Recon.psm1', 'Recon.psd1', 'PowerView.ps1', 'Get-HttpStatus.ps1', 'Invoke-ReverseDnsLookup.ps1',
               'Invoke-Portscan.ps1', 'Get-ComputerDetails.ps1', 'README.md'

}
