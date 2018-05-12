# Get-DomainGroup

## SYNOPSIS
Return all groups or specific group objects in AD.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainObject, Convert-ADName, Convert-LDAPProperty

## SYNTAX

```
Get-DomainGroup [[-Identity] <String[]>] [-MemberIdentity <String>] [-AdminCount] [-Domain <String>]
 [-LDAPFilter <String>] [-Properties <String[]>] [-SearchBase <String>] [-Server <String>]
 [-SearchScope <String>] [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-SecurityMasks <String>]
 [-Tombstone] [-FindOne] [-Credential <PSCredential>] [-Raw]
```

## DESCRIPTION
Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for all objects
matching the criteria.
To only return specific properies, use
"-Properties samaccountname,usnchanged,...".
By default, all group objects for
the current domain are returned.
To return the groups a specific user/group is
a part of, use -MemberIdentity X to execute token groups enumeration.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainGroup | select samaccountname
```

samaccountname
--------------
WinRMRemoteWMIUsers__
Administrators
Users
Guests
Print Operators
Backup Operators
...

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainGroup *admin* | select distinguishedname
```

distinguishedname
-----------------
CN=Administrators,CN=Builtin,DC=testlab,DC=local
CN=Hyper-V Administrators,CN=Builtin,DC=testlab,DC=local
CN=Schema Admins,CN=Users,DC=testlab,DC=local
CN=Enterprise Admins,CN=Users,DC=testlab,DC=local
CN=Domain Admins,CN=Users,DC=testlab,DC=local
CN=DnsAdmins,CN=Users,DC=testlab,DC=local
CN=Server Admins,CN=Users,DC=testlab,DC=local
CN=Desktop Admins,CN=Users,DC=testlab,DC=local

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainGroup -Properties samaccountname -Identity 'S-1-5-21-890171859-3433809279-3366196753-1117' | fl
```

samaccountname
--------------
Server Admins

### -------------------------- EXAMPLE 4 --------------------------
```
'CN=Desktop Admins,CN=Users,DC=testlab,DC=local' | Get-DomainGroup -Server primary.testlab.local -Verbose
```

VERBOSE: Get-DomainSearcher search string: LDAP://DC=testlab,DC=local
VERBOSE: Get-DomainGroup filter string: (&(objectCategory=group)(|(distinguishedname=CN=DesktopAdmins,CN=Users,DC=testlab,DC=local)))

usncreated            : 13245
grouptype             : -2147483646
samaccounttype        : 268435456
samaccountname        : Desktop Admins
whenchanged           : 8/10/2016 12:30:30 AM
objectsid             : S-1-5-21-890171859-3433809279-3366196753-1118
objectclass           : {top, group}
cn                    : Desktop Admins
usnchanged            : 13255
dscorepropagationdata : 1/1/1601 12:00:00 AM
name                  : Desktop Admins
distinguishedname     : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
member                : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
whencreated           : 8/10/2016 12:29:43 AM
instancetype          : 4
objectguid            : f37903ed-b333-49f4-abaa-46c65e9cca71
objectcategory        : CN=Group,CN=Schema,CN=Configuration,DC=testlab,DC=local

### -------------------------- EXAMPLE 5 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGroup -Credential $Cred

### -------------------------- EXAMPLE 6 --------------------------
```
Get-Domain | Select-Object -Expand name
```

testlab.local

'DEV\Domain Admins' | Get-DomainGroup -Verbose -Properties distinguishedname
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainGroup\] Extracted domain 'dev.testlab.local' from 'DEV\Domain Admins'
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: \[Get-DomainGroup\] filter string: (&(objectCategory=group)(|(samAccountName=Domain Admins)))

distinguishedname
-----------------
CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local

## PARAMETERS

### -Identity
A SamAccountName (e.g.
Group1), DistinguishedName (e.g.
CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to query for.
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

### -MemberIdentity
A SamAccountName (e.g.
Group1), DistinguishedName (e.g.
CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the user/group member to query for group membership.

```yaml
Type: String
Parameter Sets: (All)
Aliases: UserName

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AdminCount
Switch.
Return users with '(adminCount=1)' (meaning are/were privileged).

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

### PowerView.Group

Custom PSObject with translated group property fields.

## NOTES

## RELATED LINKS

