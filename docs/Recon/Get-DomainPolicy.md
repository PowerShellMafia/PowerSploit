# Get-DomainPolicy

## SYNOPSIS
Returns the default domain policy or the domain controller policy for the current
domain or a specified domain/domain controller.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainGPO, Get-GptTmpl, ConvertFrom-SID

## SYNTAX

```
Get-DomainPolicy [[-Domain] <String>] [-Source <String>] [-Server <String>] [-ServerTimeLimit <Int32>]
 [-ResolveSids] [-Credential <PSCredential>]
```

## DESCRIPTION
Returns the default domain policy or the domain controller policy for the current
domain or a specified domain/domain controller using Get-DomainGPO.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainPolicy
```

Returns the domain policy for the current domain.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainPolicy -Domain dev.testlab.local
```

Returns the domain policy for the dev.testlab.local domain.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainPolicy -Source DC -Domain dev.testlab.local
```

Returns the policy for the dev.testlab.local domain controller.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainPolicy -Credential $Cred

## PARAMETERS

### -Domain
The domain to query for default policies, defaults to the current domain.

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

### -Source
Extract 'Domain' or 'DC' (domain controller) policies.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Domain
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

### -ResolveSids
Switch.
Resolve Sids from a DC policy to object names.

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

### Hashtable

Ouputs a hashtable representing the parsed GptTmpl.inf file.

## NOTES

## RELATED LINKS

