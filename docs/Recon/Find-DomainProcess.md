# Find-DomainProcess

## SYNOPSIS
Searches for processes on the domain using WMI, returning processes
that match a particular user specification or process name.

Thanks to @paulbrandau for the approach idea.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-DomainUser, Get-DomainGroupMember, Get-WMIProcess, New-ThreadedFunction

## SYNTAX

### None (Default)
```
Find-DomainProcess [[-ComputerName] <String[]>] [-Domain <String>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerUnconstrained]
 [-ComputerOperatingSystem <String>] [-ComputerServicePack <String>] [-ComputerSiteName <String>]
 [-UserGroupIdentity <String[]>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>] [-StopOnSuccess] [-Delay <Int32>]
 [-Jitter <Double>] [-Threads <Int32>]
```

### TargetProcess
```
Find-DomainProcess [[-ComputerName] <String[]>] [-Domain <String>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerUnconstrained]
 [-ComputerOperatingSystem <String>] [-ComputerServicePack <String>] [-ComputerSiteName <String>]
 [-ProcessName <String[]>] [-UserGroupIdentity <String[]>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
 [-StopOnSuccess] [-Delay <Int32>] [-Jitter <Double>] [-Threads <Int32>]
```

### UserIdentity
```
Find-DomainProcess [[-ComputerName] <String[]>] [-Domain <String>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerUnconstrained]
 [-ComputerOperatingSystem <String>] [-ComputerServicePack <String>] [-ComputerSiteName <String>]
 [-UserIdentity <String[]>] [-UserGroupIdentity <String[]>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
 [-StopOnSuccess] [-Delay <Int32>] [-Jitter <Double>] [-Threads <Int32>]
```

### TargetUser
```
Find-DomainProcess [[-ComputerName] <String[]>] [-Domain <String>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerUnconstrained]
 [-ComputerOperatingSystem <String>] [-ComputerServicePack <String>] [-ComputerSiteName <String>]
 [-UserIdentity <String[]>] [-UserDomain <String>] [-UserLDAPFilter <String>] [-UserSearchBase <String>]
 [-UserGroupIdentity <String[]>] [-UserAdminCount] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
 [-StopOnSuccess] [-Delay <Int32>] [-Jitter <Double>] [-Threads <Int32>]
```

## DESCRIPTION
This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and queries the domain for users of a specified group
(default 'Domain Admins') with Get-DomainGroupMember.
Then for each server the
function enumerates any current processes running with Get-WMIProcess,
searching for processes running under any target user contexts or with the
specified -ProcessName.
If -Credential is passed, it is passed through to
the underlying WMI commands used to enumerate the remote machines.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-DomainProcess
```

Searches for processes run by 'Domain Admins' by enumerating every computer in the domain.

### -------------------------- EXAMPLE 2 --------------------------
```
Find-DomainProcess -UserAdminCount -ComputerOperatingSystem 'Windows 7*' -Domain dev.testlab.local
```

Enumerates Windows 7 computers in dev.testlab.local and returns any processes being run by
privileged users in dev.testlab.local.

### -------------------------- EXAMPLE 3 --------------------------
```
Find-DomainProcess -ProcessName putty.exe
```

Searchings for instances of putty.exe running on the current domain.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainProcess -Domain testlab.local -Credential $Cred

Searches processes being run by 'domain admins' in the testlab.local using the specified alternate credentials.

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

### -Domain
Specifies the domain to query for computers AND users, defaults to the current domain.

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

### -ComputerUnconstrained
Switch.
Search computer objects that have unconstrained delegation.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: Unconstrained

Required: False
Position: Named
Default value: False
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

### -ProcessName
Search for processes with one or more specific names.

```yaml
Type: String[]
Parameter Sets: TargetProcess
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserIdentity
Specifies one or more user identities to search for.

```yaml
Type: String[]
Parameter Sets: UserIdentity, TargetUser
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserDomain
Specifies the domain to query for users to search for, defaults to the current domain.

```yaml
Type: String
Parameter Sets: TargetUser
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserLDAPFilter
Specifies an LDAP query string that is used to search for target users.

```yaml
Type: String
Parameter Sets: TargetUser
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserSearchBase
Specifies the LDAP source to search through for target users.
e.g.
"LDAP://OU=secret,DC=testlab,DC=local".
Useful for OU queries.

```yaml
Type: String
Parameter Sets: TargetUser
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserGroupIdentity
Specifies a group identity to query for target users, defaults to 'Domain Admins.
If any other user specifications are set, then UserGroupIdentity is ignored.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: GroupName, Group

Required: False
Position: Named
Default value: Domain Admins
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserAdminCount
Switch.
Search for users users with '(adminCount=1)' (meaning are/were privileged).

```yaml
Type: SwitchParameter
Parameter Sets: TargetUser
Aliases: AdminCount

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

### -StopOnSuccess
Switch.
Stop hunting after finding after finding a target user.

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

### PowerView.UserProcess

## NOTES

## RELATED LINKS

