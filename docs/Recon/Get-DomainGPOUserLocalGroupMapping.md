# Get-DomainGPOUserLocalGroupMapping

## SYNOPSIS
Enumerates the machines where a specific domain user/group is a member of a specific
local group, all through GPO correlation.
If no user/group is specified, all
discoverable mappings are returned.

Author: @harmj0y  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPOLocalGroup, Get-DomainObject, Get-DomainComputer, Get-DomainOU, Get-DomainSite, Get-DomainGroup

## SYNTAX

```
Get-DomainGPOUserLocalGroupMapping [[-Identity] <String>] [-LocalGroup <String>] [-Domain <String>]
 [-SearchBase <String>] [-Server <String>] [-SearchScope <String>] [-ResultPageSize <Int32>]
 [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
```

## DESCRIPTION
Takes a user/group name and optional domain, and determines the computers in the domain
the user/group has local admin (or RDP) rights to.

It does this by:
    1. 
resolving the user/group to its proper SID
    2. 
enumerating all groups the user/group is a current part of
        and extracting all target SIDs to build a target SID list
    3. 
pulling all GPOs that set 'Restricted Groups' or Groups.xml by calling
        Get-DomainGPOLocalGroup
    4. 
matching the target SID list to the queried GPO SID list
        to enumerate all GPO the user is effectively applied with
    5. 
enumerating all OUs and sites and applicable GPO GUIs are
        applied to through gplink enumerating
    6. 
querying for all computers under the given OUs or sites

If no user/group is specified, all user/group -\> machine mappings discovered through
GPO relationships are returned.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-GPOLocation
```

Find all user/group -\> machine relationships where the user/group is a member
of the local administrators group on target machines.

### -------------------------- EXAMPLE 2 --------------------------
```
Find-GPOLocation -UserName dfm -Domain dev.testlab.local
```

Find all computers that dfm user has local administrator rights to in
the dev.testlab.local domain.

### -------------------------- EXAMPLE 3 --------------------------
```
Find-GPOLocation -UserName dfm -Domain dev.testlab.local
```

Find all computers that dfm user has local administrator rights to in
the dev.testlab.local domain.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainGPOUserLocalGroupMapping -Credential $Cred

## PARAMETERS

### -Identity
A SamAccountName (e.g.
harmj0y), DistinguishedName (e.g.
CN=harmj0y,CN=Users,DC=testlab,DC=local),
SID (e.g.
S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g.
4c435dd7-dc58-4b14-9a5e-1fdb0e80d201)
for the user/group to identity GPO local group mappings for.

```yaml
Type: String
Parameter Sets: (All)
Aliases: DistinguishedName, SamAccountName, Name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -LocalGroup
The local group to check access against.
Can be "Administrators" (S-1-5-32-544), "RDP/Remote Desktop Users" (S-1-5-32-555),
or a custom local SID.
Defaults to local 'Administrators'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Administrators
Accept pipeline input: False
Accept wildcard characters: False
```

### -Domain
Specifies the domain to enumerate GPOs for, defaults to the current domain.

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

### -SearchBase
{{Fill SearchBase Description}}

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

### PowerView.GPOLocalGroupMapping

A custom PSObject containing any target identity information and what local
group memberships they're a part of through GPO correlation.

## NOTES

## RELATED LINKS

[http://www.harmj0y.net/blog/redteaming/where-my-admins-at-gpo-edition/](http://www.harmj0y.net/blog/redteaming/where-my-admins-at-gpo-edition/)

