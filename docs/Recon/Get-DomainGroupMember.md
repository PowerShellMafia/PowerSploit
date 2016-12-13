# Get-DomainGroupMember

## SYNOPSIS
Return the members of a specific domain group.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainSearcher, Get-DomainGroup, Get-DomainGroupMember, Convert-ADName, Get-DomainObject, ConvertFrom-SID

## SYNTAX

### None (Default)
```
Get-DomainGroupMember [-Identity] <String[]> [-Domain <String>] [-LDAPFilter <String>] [-SearchBase <String>]
 [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>]
 [-SecurityMasks <String>] [-Tombstone] [-Credential <PSCredential>]
```

### ManualRecurse
```
Get-DomainGroupMember [-Identity] <String[]> [-Domain <String>] [-Recurse] [-LDAPFilter <String>]
 [-SearchBase <String>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-SecurityMasks <String>] [-Tombstone] [-Credential <PSCredential>]
```

### RecurseUsingMatchingRule
```
Get-DomainGroupMember [-Identity] <String[]> [-Domain <String>] [-RecurseUsingMatchingRule]
 [-LDAPFilter <String>] [-SearchBase <String>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-SecurityMasks <String>] [-Tombstone]
 [-Credential <PSCredential>]
```

## DESCRIPTION
Builds a directory searcher object using Get-DomainSearcher, builds a custom
LDAP filter based on targeting/filter parameters, and searches for the specified
group matching the criteria.
Each result is then rebound and the full user
or group object is returned.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainGroupMember "Desktop Admins"
```

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

### -------------------------- EXAMPLE 2 --------------------------
```
'Desktop Admins' | Get-DomainGroupMember -Recurse
```

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : Testing Group
MemberDistinguishedName : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberObjectClass       : group
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1129

GroupDomain             : testlab.local
GroupName               : Testing Group
GroupDistinguishedName  : CN=Testing Group,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainGroupMember -Domain testlab.local -Identity 'Desktop Admins' -RecurseUingMatchingRule
```

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : harmj0y
MemberDistinguishedName : CN=harmj0y,CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1108

GroupDomain             : testlab.local
GroupName               : Desktop Admins
GroupDistinguishedName  : CN=Desktop Admins,CN=Users,DC=testlab,DC=local
MemberDomain            : testlab.local
MemberName              : arobbins.a
MemberDistinguishedName : CN=Andy Robbins (admin),CN=Users,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-890171859-3433809279-3366196753-1112

### -------------------------- EXAMPLE 4 --------------------------
```
Get-DomainGroup *admin* -Properties samaccountname | Get-DomainGroupMember
```

### -------------------------- EXAMPLE 5 --------------------------
```
'CN=Enterprise Admins,CN=Users,DC=testlab,DC=local', 'Domain Admins' | Get-DomainGroupMember
```

### -------------------------- EXAMPLE 6 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGroupMember -Credential $Cred -Identity 'Domain Admins'

### -------------------------- EXAMPLE 7 --------------------------
```
Get-Domain | Select-Object -Expand name
```

testlab.local

'dev\domain admins' | Get-DomainGroupMember -Verbose
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
VERBOSE: \[Get-DomainGroupMember\] Extracted domain 'dev.testlab.local' from 'dev\domain admins'
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: \[Get-DomainGroupMember\] Get-DomainGroupMember filter string: (&(objectCategory=group)(|(samAccountName=domain admins)))
VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string: (&(|(distinguishedname=CN=user1,CN=Users,DC=dev,DC=testlab,DC=local)))

GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : user1
MemberDistinguishedName : CN=user1,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-201108

VERBOSE: \[Get-DomainSearcher\] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
VERBOSE: \[Get-DomainObject\] Get-DomainObject filter string: (&(|(distinguishedname=CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local)))
GroupDomain             : dev.testlab.local
GroupName               : Domain Admins
GroupDistinguishedName  : CN=Domain Admins,CN=Users,DC=dev,DC=testlab,DC=local
MemberDomain            : dev.testlab.local
MemberName              : Administrator
MemberDistinguishedName : CN=Administrator,CN=Users,DC=dev,DC=testlab,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-339048670-1233568108-4141518690-500

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

Required: True
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

### -Recurse
Switch.
If the group member is a group, recursively try to query its members as well.

```yaml
Type: SwitchParameter
Parameter Sets: ManualRecurse
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -RecurseUsingMatchingRule
Switch.
Use LDAP_MATCHING_RULE_IN_CHAIN in the LDAP search query to recurse.
Much faster than manual recursion, but doesn't reveal cross-domain groups,
and only returns user accounts (no nested group objects themselves).

```yaml
Type: SwitchParameter
Parameter Sets: RecurseUsingMatchingRule
Aliases: 

Required: False
Position: Named
Default value: False
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

### PowerView.GroupMember

Custom PSObject with translated group member property fields.

## NOTES

## RELATED LINKS

[http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/](http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/)

