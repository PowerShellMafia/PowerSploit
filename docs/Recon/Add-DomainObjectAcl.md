# Add-DomainObjectAcl

## SYNOPSIS
Adds an ACL for a specific active directory object.

AdminSDHolder ACL approach from Sean Metcalf (@pyrotek3): https://adsecurity.org/?p=1906

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainObject

## SYNTAX

```
Add-DomainObjectAcl [[-TargetIdentity] <String[]>] [-TargetDomain <String>] [-TargetLDAPFilter <String>]
 [-TargetSearchBase <String>] -PrincipalIdentity <String[]> [-PrincipalDomain <String>] [-Server <String>]
 [-SearchScope <String>] [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone]
 [-Credential <PSCredential>] [-Rights <String>] [-RightsGUID <Guid>]
```

## DESCRIPTION
This function modifies the ACL/ACE entries for a given Active Directory
target object specified by -TargetIdentity.
Available -Rights are
'All', 'ResetPassword', 'WriteMembers', 'DCSync', or a manual extended
rights GUID can be set with -RightsGUID.
These rights are granted on the target
object for the specified -PrincipalIdentity.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$Harmj0ySid = Get-DomainUser harmj0y | Select-Object -ExpandProperty objectsid
```

Get-DomainObjectACL dfm.a -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid}

...

Add-DomainObjectAcl -TargetIdentity dfm.a -PrincipalIdentity harmj0y -Rights ResetPassword -Verbose
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string: (&(|(samAccountName=harmj0y)))
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string:(&(|(samAccountName=dfm.a)))
VERBOSE: \[Add-DomainObjectAcl\] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local 'ResetPassword' on CN=dfm (admin),CN=Users,DC=testlab,DC=local
VERBOSE: \[Add-DomainObjectAcl\] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local rights GUID '00299570-246d-11d0-a768-00aa006e0529' on CN=dfm (admin),CN=Users,DC=testlab,DC=local

Get-DomainObjectACL dfm.a -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid }

AceQualifier           : AccessAllowed
ObjectDN               : CN=dfm (admin),CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-890171859-3433809279-3366196753-1114
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-890171859-3433809279-3366196753-1108
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

### -------------------------- EXAMPLE 2 --------------------------
```
$Harmj0ySid = Get-DomainUser harmj0y | Select-Object -ExpandProperty objectsid
```

Get-DomainObjectACL testuser -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid}

\[no results returned\]

$SecPassword = ConvertTo-SecureString 'Password123!'-AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-DomainObjectAcl -TargetIdentity testuser -PrincipalIdentity harmj0y -Rights ResetPassword -Credential $Cred -Verbose
VERBOSE: \[Get-Domain\] Using alternate credentials for Get-Domain
VERBOSE: \[Get-Domain\] Extracted domain 'TESTLAB' from -Credential
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainSearcher\] Using alternate credentials for LDAP connection
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string: (&(|(|(samAccountName=harmj0y)(name=harmj0y))))
VERBOSE: \[Get-Domain\] Using alternate credentials for Get-Domain
VERBOSE: \[Get-Domain\] Extracted domain 'TESTLAB' from -Credential
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainSearcher\] Using alternate credentials for LDAP connection
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string: (&(|(|(samAccountName=testuser)(name=testuser))))
VERBOSE: \[Add-DomainObjectAcl\] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local 'ResetPassword' on CN=testuser testuser,CN=Users,DC=testlab,DC=local
VERBOSE: \[Add-DomainObjectAcl\] Granting principal CN=harmj0y,CN=Users,DC=testlab,DC=local rights GUID '00299570-246d-11d0-a768-00aa006e0529' on CN=testuser,CN=Users,DC=testlab,DC=local

Get-DomainObjectACL testuser -ResolveGUIDs | Where-Object {$_.securityidentifier -eq $Harmj0ySid }

AceQualifier           : AccessAllowed
ObjectDN               : CN=dfm (admin),CN=Users,DC=testlab,DC=local
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-890171859-3433809279-3366196753-1114
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-890171859-3433809279-3366196753-1108
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

## PARAMETERS

### -TargetIdentity
A SamAccountName (e.g.
harmj0y), DistinguishedName (e.g.
CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain object to modify ACLs for.
Required.
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

### -TargetDomain
Specifies the domain for the TargetIdentity to use for the modification, defaults to the current domain.

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

### -TargetLDAPFilter
Specifies an LDAP query string that is used to filter Active Directory object targets.

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

### -TargetSearchBase
The LDAP source to search through for targets, e.g.
"LDAP://OU=secret,DC=testlab,DC=local"
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

### -PrincipalIdentity
A SamAccountName (e.g.
harmj0y), DistinguishedName (e.g.
CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the domain principal to add for the ACL.
Required.
Wildcards accepted.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PrincipalDomain
Specifies the domain for the TargetIdentity to use for the principal, defaults to the current domain.

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

### -Rights
Rights to add for the principal, 'All', 'ResetPassword', 'WriteMembers', 'DCSync'.
Defaults to 'All'.

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

### -RightsGUID
Manual GUID representing the right to add to the target.

```yaml
Type: Guid
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[https://adsecurity.org/?p=1906
https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell](https://adsecurity.org/?p=1906
https://social.technet.microsoft.com/Forums/windowsserver/en-US/df3bfd33-c070-4a9c-be98-c4da6e591a0a/forum-faq-using-powershell-to-assign-permissions-on-active-directory-objects?forum=winserverpowershell)

