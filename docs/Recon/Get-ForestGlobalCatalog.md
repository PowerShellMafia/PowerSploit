# Get-ForestGlobalCatalog

## SYNOPSIS
Return all global catalogs for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest

## SYNTAX

```
Get-ForestGlobalCatalog [[-Forest] <String>] [-Credential <PSCredential>]
```

## DESCRIPTION
Returns all global catalogs for the current forest or the forest specified
by -Forest X by using Get-Forest to retrieve the specified forest object
and the .FindAllGlobalCatalogs() to enumerate the global catalogs.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ForestGlobalCatalog
```

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestGlobalCatalog -Credential $Cred

## PARAMETERS

### -Forest
Specifies the forest name to query for global catalogs.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
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

### System.DirectoryServices.ActiveDirectory.GlobalCatalog

## NOTES

## RELATED LINKS

