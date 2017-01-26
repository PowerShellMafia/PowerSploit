# Add-DomainGroupMember

## SYNOPSIS
Adds a domain user (or group) to an existing domain group, assuming
appropriate permissions to do so.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-PrincipalContext

## SYNTAX

```
Add-DomainGroupMember [-Identity] <String> -Members <String[]> [-Domain <String>] [-Credential <PSCredential>]
```

## DESCRIPTION
First binds to the specified domain context using Get-PrincipalContext.
The bound domain context is then used to search for the specified -GroupIdentity,
which returns a DirectoryServices.AccountManagement.GroupPrincipal object.
For
each entry in -Members, each member identity is similarly searched for and added
to the group.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y'
```

Adds harmj0y to 'Domain Admins' in the current domain.

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Add-DomainGroupMember -Identity 'Domain Admins' -Members 'harmj0y' -Credential $Cred

Adds harmj0y to 'Domain Admins' in the current domain using the alternate credentials.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$UserPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
New-DomainUser -SamAccountName andy -AccountPassword $UserPassword -Credential $Cred | Add-DomainGroupMember 'Domain Admins' -Credential $Cred

Creates the 'andy' user with the specified description and password, using the specified
alternate credentials, and adds the user to 'domain admins' using Add-DomainGroupMember
and the alternate credentials.

## PARAMETERS

### -Identity
A group SamAccountName (e.g.
Group1), DistinguishedName (e.g.
CN=group1,CN=Users,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1114), or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d202)
specifying the group to add members to.

```yaml
Type: String
Parameter Sets: (All)
Aliases: GroupName, GroupIdentity

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Members
One or more member identities, i.e.
SamAccountName (e.g.
Group1), DistinguishedName
(e.g.
CN=group1,CN=Users,DC=testlab,DC=local), SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1114),
or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d202).

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: MemberIdentity, Member, DistinguishedName

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Domain
Specifies the domain to use to search for user/group principals, defaults to the current domain.

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

[http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/](http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/)

