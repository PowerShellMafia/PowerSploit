# Get-DomainManagedSecurityGroup

## SYNOPSIS
Returns all security groups in the current (or target) domain that have a manager set.

Author: Stuart Morgan (@ukstufus) \<stuart.morgan@mwrinfosecurity.com\>, Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject, Get-DomainGroup, Get-DomainObjectAcl

## SYNTAX

```
Get-DomainManagedSecurityGroup [[-Domain] <String>] [-SearchBase <String>] [-Server <String>]
 [-SearchScope <String>] [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone]
 [-Credential <PSCredential>]
```

## DESCRIPTION
Authority to manipulate the group membership of AD security groups and distribution groups
can be delegated to non-administrators by setting the 'managedBy' attribute.
This is typically
used to delegate management authority to distribution groups, but Windows supports security groups
being managed in the same way.

This function searches for AD groups which have a group manager set, and determines whether that
user can manipulate group membership.
This could be a useful method of horizontal privilege
escalation, especially if the manager can manipulate the membership of a privileged group.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainManagedSecurityGroup | Export-PowerViewCSV -NoTypeInformation group-managers.csv
```

Store a list of all security groups with managers in group-managers.csv

## PARAMETERS

### -Domain
Specifies the domain to use for the query, defaults to the current domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -SearchBase
The LDAP source to search through, e.g.
"LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.

```yaml
Type: String
Parameter Sets: (All)
Aliases: ADSPath

Required: False
Position: Named
Default value: None
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
Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).

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
for connection to the target domain.

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

## INPUTS

## OUTPUTS

### PowerView.ManagedSecurityGroup

A custom PSObject describing the managed security group.

## NOTES

## RELATED LINKS

