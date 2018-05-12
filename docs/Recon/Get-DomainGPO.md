# Get-DomainGPO

## SYNOPSIS
Return all GPOs or specific GPO objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainComputer, Get-DomainUser, Get-DomainOU, Get-NetComputerSiteName, Get-DomainSite, Get-DomainObject, Convert-LDAPProperty

## SYNTAX

### None (Default)
```
Get-DomainGPO [[-Identity] <String[]>] [-Domain <String>] [-LDAPFilter <String>] [-Properties <String[]>]
 [-SearchBase <String>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-SecurityMasks <String>] [-Tombstone] [-FindOne] [-Credential <PSCredential>]
 [-Raw]
```

### ComputerIdentity
```
Get-DomainGPO [[-Identity] <String[]>] [-ComputerIdentity <String>] [-Domain <String>] [-LDAPFilter <String>]
 [-Properties <String[]>] [-SearchBase <String>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-SecurityMasks <String>] [-Tombstone] [-FindOne]
 [-Credential <PSCredential>] [-Raw]
```

### UserIdentity
```
Get-DomainGPO [[-Identity] <String[]>] [-UserIdentity <String>] [-Domain <String>] [-LDAPFilter <String>]
 [-Properties <String[]>] [-SearchBase <String>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-SecurityMasks <String>] [-Tombstone] [-FindOne]
 [-Credential <PSCredential>] [-Raw]
```

## DESCRIPTION
Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria.
To only return specific properies, use
"-Properties samaccountname,usnchanged,...".
By default, all GPO objects for
the current domain are returned.
To enumerate all GPOs that are applied to
a particular machine, use -ComputerName X.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainGPO -Domain testlab.local
```

Return all GPOs for the testlab.local domain

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainGPO -ComputerName windows1.testlab.local
```

Returns all GPOs applied windows1.testlab.local

### -------------------------- EXAMPLE 3 --------------------------
```
"{F260B76D-55C8-46C5-BEF1-9016DD98E272}","Test GPO" | Get-DomainGPO
```

Return the GPOs with the name of "{F260B76D-55C8-46C5-BEF1-9016DD98E272}" and the display
name of "Test GPO"

### -------------------------- EXAMPLE 4 --------------------------
```
Get-DomainGPO -LDAPFilter '(!primarygroupid=513)' -Properties samaccountname,lastlogon
```

### -------------------------- EXAMPLE 5 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPO -Credential $Cred

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

### -ComputerIdentity
Return all GPO objects applied to a given computer identity (name, dnsname, DistinguishedName, etc.).

```yaml
Type: String
Parameter Sets: ComputerIdentity
Aliases: ComputerName

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserIdentity
Return all GPO objects applied to a given user identity (name, SID, DistinguishedName, etc.).

```yaml
Type: String
Parameter Sets: UserIdentity
Aliases: UserName

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

### PowerView.GPO

Custom PSObject with translated GPO property fields.

PowerView.GPO.Raw

The raw DirectoryServices.SearchResult object, if -Raw is enabled.

## NOTES

## RELATED LINKS

