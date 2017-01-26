# ConvertTo-SID

## SYNOPSIS
Converts a given user/group name to a security identifier (SID).

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Convert-ADName, Get-DomainObject, Get-Domain

## SYNTAX

```
ConvertTo-SID [-ObjectName] <String[]> [[-Domain] <String>] [[-Server] <String>] [[-Credential] <PSCredential>]
```

## DESCRIPTION
Converts a "DOMAIN\username" syntax to a security identifier (SID)
using System.Security.Principal.NTAccount's translate function.
If alternate
credentials are supplied, then Get-ADObject is used to try to map the name
to a security identifier.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
ConvertTo-SID 'DEV\dfm'
```

### -------------------------- EXAMPLE 2 --------------------------
```
'DEV\dfm','DEV\krbtgt' | ConvertTo-SID
```

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
'TESTLAB\dfm' | ConvertTo-SID -Credential $Cred

## PARAMETERS

### -ObjectName
The user/group name to convert, can be 'user' or 'DOMAIN\user' format.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Name, Identity

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Domain
Specifies the domain to use for the translation, defaults to the current domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Server
Specifies an Active Directory server (domain controller) to bind to for the translation.

```yaml
Type: String
Parameter Sets: (All)
Aliases: DomainController

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
Specifies an alternate credential to use for the translation.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases: 

Required: False
Position: 4
Default value: [Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

### String

Accepts one or more username specification strings on the pipeline.

## OUTPUTS

### String

A string representing the SID of the translated name.

## NOTES

## RELATED LINKS

