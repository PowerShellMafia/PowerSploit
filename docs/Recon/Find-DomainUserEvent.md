# Find-DomainUserEvent

## SYNOPSIS
Finds logon events on the current (or remote domain) for the specified users.

Author: Lee Christensen (@tifkin_), Justin Warner (@sixdub), Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainUser, Get-DomainGroupMember, Get-DomainController, Get-DomainUserEvent, New-ThreadedFunction

## SYNTAX

### Domain (Default)
```
Find-DomainUserEvent [-Domain <String>] [-Filter <Hashtable>] [-StartTime <DateTime>] [-EndTime <DateTime>]
 [-MaxEvents <Int32>] [-UserIdentity <String[]>] [-UserDomain <String>] [-UserLDAPFilter <String>]
 [-UserSearchBase <String>] [-UserGroupIdentity <String[]>] [-UserAdminCount] [-CheckAccess] [-Server <String>]
 [-SearchScope <String>] [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone]
 [-Credential <PSCredential>] [-StopOnSuccess] [-Delay <Int32>] [-Jitter <Double>] [-Threads <Int32>]
```

### ComputerName
```
Find-DomainUserEvent [[-ComputerName] <String[]>] [-Filter <Hashtable>] [-StartTime <DateTime>]
 [-EndTime <DateTime>] [-MaxEvents <Int32>] [-UserIdentity <String[]>] [-UserDomain <String>]
 [-UserLDAPFilter <String>] [-UserSearchBase <String>] [-UserGroupIdentity <String[]>] [-UserAdminCount]
 [-CheckAccess] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>]
 [-Tombstone] [-Credential <PSCredential>] [-StopOnSuccess] [-Delay <Int32>] [-Jitter <Double>]
 [-Threads <Int32>]
```

## DESCRIPTION
Enumerates all domain controllers from the specified -Domain
(default of the local domain) using Get-DomainController, enumerates
the logon events for each using Get-DomainUserEvent, and filters
the results based on the targeting criteria.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-DomainUserEvent
```

Search for any user events matching domain admins on every DC in the current domain.

### -------------------------- EXAMPLE 2 --------------------------
```
$cred = Get-Credential dev\administrator
```

Find-DomainUserEvent -ComputerName 'secondary.dev.testlab.local' -UserIdentity 'john'

Search for any user events matching the user 'john' on the 'secondary.dev.testlab.local'
domain controller using the alternate credential

### -------------------------- EXAMPLE 3 --------------------------
```
'primary.testlab.local | Find-DomainUserEvent -Filter @{'IpAddress'='192.168.52.200|192.168.52.201'}
```

Find user events on the primary.testlab.local system where the event matches
the IPAddress '192.168.52.200' or '192.168.52.201'.

### -------------------------- EXAMPLE 4 --------------------------
```
$cred = Get-Credential testlab\administrator
```

Find-DomainUserEvent -Delay 1 -Filter @{'LogonGuid'='b8458aa9-b36e-eaa1-96e0-4551000fdb19'; 'TargetLogonId' = '10238128'; 'op'='&'}

Find user events mathing the specified GUID AND the specified TargetLogonId, searching
through every domain controller in the current domain, enumerating each DC in serial
instead of in a threaded manner, using the alternate credential.

## PARAMETERS

### -ComputerName
Specifies an explicit computer name to retrieve events from.

```yaml
Type: String[]
Parameter Sets: ComputerName
Aliases: dnshostname, HostName, name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Domain
Specifies a domain to query for domain controllers to enumerate.
Defaults to the current domain.

```yaml
Type: String
Parameter Sets: Domain
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Filter
A hashtable of PowerView.LogonEvent properties to filter for.
The 'op|operator|operation' clause can have '&', '|', 'and', or 'or',
and is 'or' by default, meaning at least one clause matches instead of all.
See the exaples for usage.

```yaml
Type: Hashtable
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -StartTime
The \[DateTime\] object representing the start of when to collect events.
Default of \[DateTime\]::Now.AddDays(-1).

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: [DateTime]::Now.AddDays(-1)
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -EndTime
The \[DateTime\] object representing the end of when to collect events.
Default of \[DateTime\]::Now.

```yaml
Type: DateTime
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: [DateTime]::Now
Accept pipeline input: True (ByPropertyName)
Accept wildcard characters: False
```

### -MaxEvents
The maximum number of events (per host) to retrieve.
Default of 5000.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 5000
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserIdentity
Specifies one or more user identities to search for.

```yaml
Type: String[]
Parameter Sets: (All)
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
Parameter Sets: (All)
Aliases: AdminCount

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -CheckAccess
{{Fill CheckAccess Description}}

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
for connection to the target computer(s).

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

### PowerView.LogonEvent

PowerView.ExplicitCredentialLogon

## NOTES

## RELATED LINKS

[http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/](http://www.sixdub.net/2014/11/07/offensive-event-parsing-bringing-home-trophies/)

