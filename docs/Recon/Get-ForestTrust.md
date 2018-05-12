# Get-ForestTrust

## SYNOPSIS
Return all forest trusts for the current forest or a specified forest.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Forest

## SYNTAX

```
Get-ForestTrust [[-Forest] <String>] [-Credential <PSCredential>]
```

## DESCRIPTION
This function will enumerate domain trust relationships for the current (or a remote)
forest using number of method using the .NET method GetAllTrustRelationships() on a
System.DirectoryServices.ActiveDirectory.Forest returned by Get-Forest.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ForestTrust
```

Return current forest trusts.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-ForestTrust -Forest "external.local"
```

Return trusts for the "external.local" forest.

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-ForestTrust -Forest "external.local" -Credential $Cred

Return trusts for the "external.local" forest using the specified alternate credenitals.

## PARAMETERS

### -Forest
Specifies the forest to query for trusts, defaults to the current forest.

```yaml
Type: String
Parameter Sets: (All)
Aliases: Name

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
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

### PowerView.DomainTrust.NET

A TrustRelationshipInformationCollection returned when using .NET methods (default).

## NOTES

## RELATED LINKS

