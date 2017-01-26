# Get-ForestDomain

## SYNOPSIS
Return all domains for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest

## SYNTAX

```
Get-ForestDomain [[-Forest] <String>] [-Credential <PSCredential>]
```

## DESCRIPTION
Returns all domains for the current forest or the forest specified
by -Forest X.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ForestDomain
```

### -------------------------- EXAMPLE 2 --------------------------
```
Get-ForestDomain -Forest external.local
```

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestDomain -Credential $Cred

## PARAMETERS

### -Forest
Specifies the forest name to query for domains.

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
for connection to the target forest.

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

### System.DirectoryServices.ActiveDirectory.Domain

## NOTES

## RELATED LINKS

