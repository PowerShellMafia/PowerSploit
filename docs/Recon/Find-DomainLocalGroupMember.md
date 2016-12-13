# Find-DomainLocalGroupMember

## SYNOPSIS
Enumerates the members of specified local group (default administrators)
for all the targeted machines on the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetLocalGroupMember, New-ThreadedFunction

## SYNTAX

```
Find-DomainLocalGroupMember [[-ComputerName] <String[]>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerOperatingSystem <String>]
 [-ComputerServicePack <String>] [-ComputerSiteName <String>] [-GroupName <String>] [-Method <String>]
 [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone]
 [-Credential <PSCredential>] [-Delay <Int32>] [-Jitter <Double>] [-Threads <Int32>]
```

## DESCRIPTION
This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and enumerates the members of the specified local
group (default of Administrators) for each machine using Get-NetLocalGroupMember.
By default, the API method is used, but this can be modified with '-Method winnt'
to use the WinNT service provider.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-DomainLocalGroupMember
```

Enumerates the local group memberships for all reachable machines in the current domain.

### -------------------------- EXAMPLE 2 --------------------------
```
Find-DomainLocalGroupMember -Domain dev.testlab.local
```

Enumerates the local group memberships for all reachable machines the dev.testlab.local domain.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainLocalGroupMember -Domain testlab.local -Credential $Cred

Enumerates the local group memberships for all reachable machines the dev.testlab.local
domain using the alternate credentials.

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

### -GroupName
The local group name to query for users.
If not given, it defaults to "Administrators".

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Administrators
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -Method
The collection method to use, defaults to 'API', also accepts 'WinNT'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: CollectionMethod

Required: False
Position: Named
Default value: API
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

### PowerView.LocalGroupMember.API

Custom PSObject with translated group property fields from API results.

PowerView.LocalGroupMember.WinNT

Custom PSObject with translated group property fields from WinNT results.

## NOTES

## RELATED LINKS

