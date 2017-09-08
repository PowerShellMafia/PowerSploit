# Get-DomainOU

## SYNOPSIS
Search for all organization units (OUs) or specific OU objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty

## SYNTAX

```
Get-DomainOU [[-Identity] <String[]>] [-GPLink <String>] [-Domain <String>] [-LDAPFilter <String>]
 [-Properties <String[]>] [-SearchBase <String>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-SecurityMasks <String>] [-Tombstone] [-FindOne]
 [-Credential <PSCredential>] [-Raw]
```

## DESCRIPTION
Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria.
To only return specific properies, use
"-Properties whencreated,usnchanged,...".
By default, all OU objects for
the current domain are returned.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainOU
```

Returns the current OUs in the domain.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainOU *admin* -Domain testlab.local
```

Returns all OUs with "admin" in their name in the testlab.local domain.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainOU -GPLink "F260B76D-55C8-46C5-BEF1-9016DD98E272"
```

Returns all OUs with linked to the specified group policy object.

### -------------------------- EXAMPLE 4 --------------------------
```
"*admin*","*server*" | Get-DomainOU
```

Search for OUs with the specific names.

### -------------------------- EXAMPLE 5 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainOU -Credential $Cred

## PARAMETERS

### -Identity
An OU name (e.g.
TestOU), DistinguishedName (e.g.
OU=TestOU,DC=testlab,DC=local), or
GUID (e.g.
8a9ba22a-8977-47e6-84ce-8c26af4e1e6a).
Wildcards accepted.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -GPLink
Only return OUs with the specified GUID in their gplink property.

```yaml
Type: String
Parameter Sets: (All)
Aliases: GUID

Required: False
Position: Named
Default value: None
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

### -Properties
Specifies the properties of the output object to retrieve from the server.

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

### -SecurityMasks
Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.

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

### -FindOne
Only return one result object.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: ReturnOne

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

### -Raw
Switch.
Return raw results instead of translating the fields into a custom PSObject.

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

## INPUTS

## OUTPUTS

### PowerView.OU

Custom PSObject with translated OU property fields.

## NOTES

## RELATED LINKS

