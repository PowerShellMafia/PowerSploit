# Find-DomainObjectPropertyOutlier

## SYNOPSIS
Finds user/group/computer objects in AD that have 'outlier' properties set.

Author: Will Schroeder (@harmj0y), Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain, Get-DomainUser, Get-DomainGroup, Get-DomainComputer, Get-ForestSchemaClass

## SYNTAX

### ClassName (Default)
```
Find-DomainObjectPropertyOutlier [-ClassName] <String> [-ReferencePropertySet <String[]>] [-Domain <String>]
 [-LDAPFilter <String>] [-SearchBase <String>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
```

### ReferenceObject
```
Find-DomainObjectPropertyOutlier [-ReferencePropertySet <String[]>] -ReferenceObject <PSObject>
 [-Domain <String>] [-LDAPFilter <String>] [-SearchBase <String>] [-Server <String>] [-SearchScope <String>]
 [-ResultPageSize <Int32>] [-ServerTimeLimit <Int32>] [-Tombstone] [-Credential <PSCredential>]
```

## DESCRIPTION
Enumerates the schema for the specified -ClassName (if passed) by using Get-ForestSchemaClass.
If a -ReferenceObject is passed, the class is extracted from the passed object.
A 'reference' set of property names is then calculated, either from a standard set preserved
for user/group/computers, or from the array of names passed to -ReferencePropertySet, or
from the property names of the passed -ReferenceObject.
These property names are substracted
from the master schema propertyu name list to retrieve a set of 'non-standard' properties.
Every user/group/computer object (depending on determined class) are enumerated, and for each
object, if the object has a 'non-standard' property set, the object samAccountName, property
name, and property value are output to the pipeline.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-DomainObjectPropertyOutlier -User
```

Enumerates users in the current domain with 'outlier' properties filled in.

### -------------------------- EXAMPLE 2 --------------------------
```
Find-DomainObjectPropertyOutlier -Group -Domain external.local
```

Enumerates groups in the external.local forest/domain with 'outlier' properties filled in.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainComputer -FindOne | Find-DomainObjectPropertyOutlier
```

Enumerates computers in the current domain with 'outlier' properties filled in.

## PARAMETERS

### -ClassName
Specifies the AD object class to find property outliers for, 'user', 'group', or 'computer'.
If -ReferenceObject is specified, this will be automatically extracted, if possible.

```yaml
Type: String
Parameter Sets: ClassName
Aliases: Class

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ReferencePropertySet
Specifies an array of property names to diff against the class schema.

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

### -ReferenceObject
Specicifes the PowerView user/group/computer object to extract property names
from to use as the reference set.

```yaml
Type: PSObject
Parameter Sets: ReferenceObject
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
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

### PowerView.PropertyOutlier

Custom PSObject with translated object property outliers.

## NOTES

## RELATED LINKS

