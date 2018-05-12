# Get-Forest

## SYNOPSIS
Returns the forest object for the current (or specified) forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: ConvertTo-SID

## SYNTAX

```
Get-Forest [[-Forest] <String>] [-Credential <PSCredential>]
```

## DESCRIPTION
Returns a System.DirectoryServices.ActiveDirectory.Forest object for the current
forest or the forest specified with -Forest X.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-Forest -Forest external.domain
```

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-Forest -Credential $Cred

## PARAMETERS

### -Forest
The forest name to query for, defaults to the current forest.

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

### System.Management.Automation.PSCustomObject

Outputs a PSObject containing System.DirectoryServices.ActiveDirectory.Forest in addition
to the forest root domain SID.

## NOTES

## RELATED LINKS

