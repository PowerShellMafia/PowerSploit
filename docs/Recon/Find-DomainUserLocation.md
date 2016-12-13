# Find-DomainUserLocation

## SYNOPSIS
Finds domain machines where specific users are logged into.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainFileServer, Get-DomainDFSShare, Get-DomainController, Get-DomainComputer, Get-DomainUser, Get-DomainGroupMember, Invoke-UserImpersonation, Invoke-RevertToSelf, Get-NetSession, Test-AdminAccess, Get-NetLoggedon, Resolve-IPAddress, New-ThreadedFunction

## SYNTAX

### UserGroupIdentity (Default)
```
Find-DomainUserLocation [[-ComputerName] <String[]>] [-Domain <String>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerUnconstrained]
 [-ComputerOperatingSystem <String>] [-ComputerServicePack <String>] [-ComputerSiteName <String>]
 [-UserDomain <String>] [-UserLDAPFilter <String>] [-UserSearchBase <String>] [-UserGroupIdentity <String[]>]
 [-UserAdminCount] [-UserAllowDelegation] [-CheckAccess] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
 [-StopOnSuccess] [-Delay <Int32>] [-Jitter <Double>] [-Stealth] [-StealthSource <String>] [-Threads <Int32>]
```

### UserIdentity
```
Find-DomainUserLocation [[-ComputerName] <String[]>] [-Domain <String>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerUnconstrained]
 [-ComputerOperatingSystem <String>] [-ComputerServicePack <String>] [-ComputerSiteName <String>]
 [-UserIdentity <String[]>] [-UserDomain <String>] [-UserLDAPFilter <String>] [-UserSearchBase <String>]
 [-UserAdminCount] [-UserAllowDelegation] [-CheckAccess] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
 [-StopOnSuccess] [-Delay <Int32>] [-Jitter <Double>] [-Stealth] [-StealthSource <String>] [-Threads <Int32>]
```

### ShowAll
```
Find-DomainUserLocation [[-ComputerName] <String[]>] [-Domain <String>] [-ComputerDomain <String>]
 [-ComputerLDAPFilter <String>] [-ComputerSearchBase <String>] [-ComputerUnconstrained]
 [-ComputerOperatingSystem <String>] [-ComputerServicePack <String>] [-ComputerSiteName <String>]
 [-UserDomain <String>] [-UserLDAPFilter <String>] [-UserSearchBase <String>] [-UserAdminCount]
 [-UserAllowDelegation] [-CheckAccess] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>] [-StopOnSuccess] [-Delay <Int32>]
 [-Jitter <Double>] [-ShowAll] [-Stealth] [-StealthSource <String>] [-Threads <Int32>]
```

## DESCRIPTION
This function enumerates all machines on the current (or specified) domain
using Get-DomainComputer, and queries the domain for users of a specified group
(default 'Domain Admins') with Get-DomainGroupMember.
Then for each server the
function enumerates any active user sessions with Get-NetSession/Get-NetLoggedon
The found user list is compared against the target list, and any matches are
displayed.
If -ShowAll is specified, all results are displayed instead of
the filtered set.
If -Stealth is specified, then likely highly-trafficed servers
are enumerated with Get-DomainFileServer/Get-DomainController, and session
enumeration is executed only against those servers.
If -Credential is passed,
then Invoke-UserImpersonation is used to impersonate the specified user
before enumeration, reverting after with Invoke-RevertToSelf.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-DomainUserLocation
```

Searches for 'Domain Admins' by enumerating every computer in the domain.

### -------------------------- EXAMPLE 2 --------------------------
```
Find-DomainUserLocation -Stealth -ShowAll
```

Enumerates likely highly-trafficked servers, performs just session enumeration
against each, and outputs all results.

### -------------------------- EXAMPLE 3 --------------------------
```
Find-DomainUserLocation -UserAdminCount -ComputerOperatingSystem 'Windows 7*' -Domain dev.testlab.local
```

Enumerates Windows 7 computers in dev.testlab.local and returns user results for privileged
users in dev.testlab.local.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-DomainUserLocation -Domain testlab.local -Credential $Cred

Searches for domain admin locations in the testlab.local using the specified alternate credentials.

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

### -UserIdentity
Specifies one or more user identities to search for.

```yaml
Type: String[]
Parameter Sets: UserIdentity
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
Parameter Sets: (All)
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
Parameter Sets: (All)
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
Parameter Sets: (All)
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
Parameter Sets: UserGroupIdentity
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
Parameter Sets: (All)
Aliases: AdminCount

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserAllowDelegation
Switch.
Search for user accounts that are not marked as 'sensitive and not allowed for delegation'.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: AllowDelegation

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -CheckAccess
Switch.
Check if the current user has local admin access to computers where target users are found.

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

### -ShowAll
Switch.
Return all user location results instead of filtering based on target
specifications.

```yaml
Type: SwitchParameter
Parameter Sets: ShowAll
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Stealth
Switch.
Only enumerate sessions from connonly used target servers.

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

### -StealthSource
The source of target servers to use, 'DFS' (distributed file servers),
'DC' (domain controllers), 'File' (file servers), or 'All' (the default).

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: All
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

### PowerView.UserLocation

## NOTES

## RELATED LINKS

