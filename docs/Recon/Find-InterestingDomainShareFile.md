# Find-InterestingDomainShareFile

## SYNOPSIS
Searches for files matching specific criteria on readable shares
in the domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetShare, Find-InterestingFile, New-ThreadedFunction

## SYNTAX

### FileSpecification (Default)
```
Find-InterestingDomainShareFile [[-ComputerName] <String[]>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerOperatingSystem <String>]
 [-ComputerServicePack <String>] [-ComputerSiteName <String>] [-Include <String[]>] [-SharePath <String[]>]
 [-ExcludedShares <String[]>] [-LastAccessTime <DateTime>] [-LastWriteTime <DateTime>]
 [-CreationTime <DateTime>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>] [-Delay <Int32>] [-Jitter <Double>]
 [-Threads <Int32>]
```

### OfficeDocs
```
Find-InterestingDomainShareFile [[-ComputerName] <String[]>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerOperatingSystem <String>]
 [-ComputerServicePack <String>] [-ComputerSiteName <String>] [-SharePath <String[]>]
 [-ExcludedShares <String[]>] [-OfficeDocs] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
 [-Delay <Int32>] [-Jitter <Double>] [-Threads <Int32>]
```

### FreshEXEs
```
Find-InterestingDomainShareFile [[-ComputerName] <String[]>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerOperatingSystem <String>]
 [-ComputerServicePack <String>] [-ComputerSiteName <String>] [-SharePath <String[]>]
 [-ExcludedShares <String[]>] [-FreshEXEs] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>] [-Delay <Int32>] [-Jitter <Double>]
 [-Threads <Int32>]
```

## DESCRIPTION
This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the available shares for each
machine with Get-NetShare.
It will then use Find-InterestingFile on each
readhable share, searching for files marching specific criteria.
If -Credential
is passed, then Invoke-UserImpersonation is used to impersonate the specified
user before enumeration, reverting after with Invoke-RevertToSelf.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-InterestingDomainShareFile
```

Finds 'interesting' files on the current domain.

### -------------------------- EXAMPLE 2 --------------------------
```
Find-InterestingDomainShareFile -ComputerName @('windows1.testlab.local','windows2.testlab.local')
```

Finds 'interesting' files on readable shares on the specified systems.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('DEV\dfm.a', $SecPassword)
Find-DomainShare -Domain testlab.local -Credential $Cred

Searches interesting files in the testlab.local domain using the specified alternate credentials.

## PARAMETERS

### -ComputerName
Specifies an array of one or more hosts to enumerate, passable on the pipeline.
If -ComputerName is not passed, the default behavior is to enumerate all machines
in the domain returned by Get-DomainComputer.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: DNSHostName

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ComputerDomain
Specifies the domain to query for computers, defaults to the current domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerLDAPFilter
Specifies an LDAP query string that is used to search for computer objects.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerSearchBase
Specifies the LDAP source to search through for computers,
e.g.
"LDAP://OU=secret,DC=testlab,DC=local".
Useful for OU queries.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerOperatingSystem
Search computers with a specific operating system, wildcards accepted.

```yaml
Type: String
Parameter Sets: (All)
Aliases: OperatingSystem

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerServicePack
Search computers with a specific service pack, wildcards accepted.

```yaml
Type: String
Parameter Sets: (All)
Aliases: ServicePack

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerSiteName
Search computers in the specific AD Site name, wildcards accepted.

```yaml
Type: String
Parameter Sets: (All)
Aliases: SiteName

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Include
Only return files/folders that match the specified array of strings,
i.e.
@(*.doc*, *.xls*, *.ppt*)

```yaml
Type: String[]
Parameter Sets: FileSpecification
Aliases: SearchTerms, Terms

Required: False
Position: Named
Default value: @('*password*', '*sensitive*', '*admin*', '*login*', '*secret*', 'unattend*.xml', '*.vmdk', '*creds*', '*credential*', '*.config')
Accept pipeline input: False
Accept wildcard characters: False
```

### -SharePath
Specifies one or more specific share paths to search, in the form \\\\COMPUTER\Share

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Share

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ExcludedShares
Specifies share paths to exclude, default of C$, Admin$, Print$, IPC$.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: @('C$', 'Admin$', 'Print$', 'IPC$')
Accept pipeline input: False
Accept wildcard characters: False
```

### -LastAccessTime
Only return files with a LastAccessTime greater than this date value.

```yaml
Type: DateTime
Parameter Sets: FileSpecification
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -LastWriteTime
Only return files with a LastWriteTime greater than this date value.

```yaml
Type: DateTime
Parameter Sets: FileSpecification
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -CreationTime
Only return files with a CreationTime greater than this date value.

```yaml
Type: DateTime
Parameter Sets: FileSpecification
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OfficeDocs
Switch.
Search for office documents (*.doc*, *.xls*, *.ppt*)

```yaml
Type: SwitchParameter
Parameter Sets: OfficeDocs
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -FreshEXEs
Switch.
Find .EXEs accessed within the last 7 days.

```yaml
Type: SwitchParameter
Parameter Sets: FreshEXEs
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
Specifies an Active Directory server (domain controller) to bind to.

```yaml
Type: String
Parameter Sets: (All)
Aliases: DomainController

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SearchScope
Specifies the scope to search under for computers, Base/OneLevel/Subtree (default of Subtree).

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Subtree
Accept pipeline input: False
Accept wildcard characters: False
```

### -ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 200
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServerTimeLimit
Specifies the maximum amount of time the server spends searching.
Default of 120 seconds.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Tombstone
Switch.
Specifies that the searcher should also return deleted/tombstoned objects.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object of alternate credentials
for connection to the target domain and target systems.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: [Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -Delay
Specifies the delay (in seconds) between enumerating hosts, defaults to 0.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Jitter
Specifies the jitter (0-1.0) to apply to any specified -Delay, defaults to +/- 0.3

```yaml
Type: Double
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 0.3
Accept pipeline input: False
Accept wildcard characters: False
```

### -Threads
The number of threads to use for user searching, defaults to 20.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 20
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### PowerView.FoundFile

## NOTES

## RELATED LINKS

