# Get-DomainObject

## SYNOPSIS
Return all (or specified) domain objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Convert-LDAPProperty, Convert-ADName

## SYNTAX

```
Get-DomainObject [[-Identity] <String[]>] [-Domain <String>] [-LDAPFilter <String>] [-Properties <String[]>]
 [-SearchBase <String>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-SecurityMasks <String>] [-Tombstone] [-FindOne] [-Credential <PSCredential>]
 [-Raw]
```

## DESCRIPTION
Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria.
To only return specific properies, use
"-Properties samaccountname,usnchanged,...".
By default, all objects for
the current domain are returned.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainObject -Domain testlab.local
```

Return all objects for the testlab.local domain

### -------------------------- EXAMPLE 2 --------------------------
```
'S-1-5-21-890171859-3433809279-3366196753-1003', 'CN=dfm,CN=Users,DC=testlab,DC=local','b6a9a2fb-bbd5-4f28-9a09-23213cea6693','dfm.a' | Get-DomainObject -Properties distinguishedname
```

distinguishedname
-----------------
CN=PRIMARY,OU=Domain Controllers,DC=testlab,DC=local
CN=dfm,CN=Users,DC=testlab,DC=local
OU=OU3,DC=testlab,DC=local
CN=dfm (admin),CN=Users,DC=testlab,DC=local

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainObject -Credential $Cred -Identity 'windows1'

### -------------------------- EXAMPLE 4 --------------------------
```
Get-Domain | Select-Object -Expand name
```

testlab.local

'testlab\harmj0y','DEV\Domain Admins' | Get-DomainObject -Verbose -Properties distinguishedname
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainUser\] Extracted domain 'testlab.local' from 'testlab\harmj0y'
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string: (&(|(samAccountName=harmj0y)))

distinguishedname
-----------------
CN=harmj0y,CN=Users,DC=testlab,DC=local
VERBOSE: \[Get-DomainUser\] Extracted domain 'dev.testlab.local' from 'DEV\Domain Admins'
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string: (&(|(samAccountName=Domain Admins)))
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

## PARAMETERS

### -Identity
A SamAccountName (e.g.
harmj0y), DistinguishedName (e.g.
CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
Wildcards accepted.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: DistinguishedName, SamAccountName, Name, MemberDistinguishedName, MemberName

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
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

### PowerView.ADObject

Custom PSObject with translated AD object property fields.

PowerView.ADObject.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.

## NOTES

## RELATED LINKS

