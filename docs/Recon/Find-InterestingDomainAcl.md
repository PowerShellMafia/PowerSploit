# Find-InterestingDomainAcl

## SYNOPSIS
Finds object ACLs in the current (or specified) domain with modification
rights set to non-built in objects.

Thanks Sean Metcalf (@pyrotek3) for the idea and guidance.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObjectAcl, Get-DomainObject, Convert-ADName

## SYNTAX

```
Find-InterestingDomainAcl [[-Domain] <String>] [-ResolveGUIDs] [-RightsFilter <String>] [-LDAPFilter <String>]
 [-SearchBase <String>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
```

## DESCRIPTION
This function enumerates the ACLs for every object in the domain with Get-DomainObjectAcl,
and for each returned ACE entry it checks if principal security identifier
is *-1000 (meaning the account is not built in), and also checks if the rights for
the ACE mean the object can be modified by the principal.
If these conditions are met,
then the security identifier SID is translated, the domain object is retrieved, and
additional IdentityReference* information is appended to the output object.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-InterestingDomainAcl
```

Finds interesting object ACLS in the current domain.

### -------------------------- EXAMPLE 2 --------------------------
```
Find-InterestingDomainAcl -Domain dev.testlab.local -ResolveGUIDs
```

Finds interesting object ACLS in the ev.testlab.local domain and
resolves rights GUIDs to display names.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Find-InterestingDomainAcl -Credential $Cred -ResolveGUIDs

## PARAMETERS

### -Domain
Specifies the domain to use for the query, defaults to the current domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases: DomainName, Name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ResolveGUIDs
Switch.
Resolve GUIDs to their display names.

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

### -RightsFilter
{{Fill RightsFilter Description}}

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

### -LDAPFilter
Specifies an LDAP query string that is used to filter Active Directory objects.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Filter

Required: False
Position: Named
Default value: None
Accept pipeline input: False
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

### PowerView.ACL

Custom PSObject with ACL entries.

## NOTES

## RELATED LINKS

