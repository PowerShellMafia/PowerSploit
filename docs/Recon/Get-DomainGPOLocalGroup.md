# Get-DomainGPOLocalGroup

## SYNOPSIS
Returns all GPOs in a domain that modify local group memberships through 'Restricted Groups'
or Group Policy preferences.
Also return their user membership mappings, if they exist.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPO, Get-GptTmpl, Get-GroupsXML, ConvertTo-SID, ConvertFrom-SID

## SYNTAX

```
Get-DomainGPOLocalGroup [[-Identity] <String[]>] [-ResolveMembersToSIDs] [-Domain <String>]
 [-LDAPFilter <String>] [-SearchBase <String>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
```

## DESCRIPTION
First enumerates all GPOs in the current/target domain using Get-DomainGPO with passed
arguments, and for each GPO checks if 'Restricted Groups' are set with GptTmpl.inf or
group membership is set through Group Policy Preferences groups.xml files.
For any
GptTmpl.inf files found, the file is parsed with Get-GptTmpl and any 'Group Membership'
section data is processed if present.
Any found Groups.xml files are parsed with
Get-GroupsXML and those memberships are returned as well.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainGPOLocalGroup
```

Returns all local groups set by GPO along with their members and memberof.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainGPOLocalGroup -ResolveMembersToSIDs
```

Returns all local groups set by GPO along with their members and memberof,
and resolve any members to their domain SIDs.

### -------------------------- EXAMPLE 3 --------------------------
```
'{0847C615-6C4E-4D45-A064-6001040CC21C}' | Get-DomainGPOLocalGroup
```

Return any GPO-set groups for the GPO with the given name/GUID.

### -------------------------- EXAMPLE 4 --------------------------
```
Get-DomainGPOLocalGroup 'Desktops'
```

Return any GPO-set groups for the GPO with the given display name.

### -------------------------- EXAMPLE 5 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOLocalGroup -Credential $Cred

## PARAMETERS

### -Identity
A display name (e.g.
'Test GPO'), DistinguishedName (e.g.
'CN={F260B76D-55C8-46C5-BEF1-9016DD98E272},CN=Policies,CN=System,DC=testlab,DC=local'),
GUID (e.g.
'10ec320d-3111-4ef4-8faf-8f14f4adc789'), or GPO name (e.g.
'{F260B76D-55C8-46C5-BEF1-9016DD98E272}').
Wildcards accepted.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: DistinguishedName, SamAccountName, Name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ResolveMembersToSIDs
Switch.
Indicates that any member names should be resolved to their domain SIDs.

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

### -Domain
Specifies the domain to use for the query, defaults to the current domain.

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

### PowerView.GPOGroup

## NOTES

## RELATED LINKS

[https://morgansimonsenblog.azurewebsites.net/tag/groups/](https://morgansimonsenblog.azurewebsites.net/tag/groups/)

