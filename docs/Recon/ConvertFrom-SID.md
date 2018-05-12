# ConvertFrom-SID

## SYNOPSIS
Converts a security identifier (SID) to a group/user name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Convert-ADName

## SYNTAX

```
ConvertFrom-SID [-ObjectSid] <String[]> [[-Domain] <String>] [[-Server] <String>]
 [[-Credential] <PSCredential>]
```

## DESCRIPTION
Converts a security identifier string (SID) to a group/user name
using Convert-ADName.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108
```

TESTLAB\harmj0y

### -------------------------- EXAMPLE 2 --------------------------
```
"S-1-5-21-890171859-3433809279-3366196753-1107", "S-1-5-21-890171859-3433809279-3366196753-1108", "S-1-5-32-562" | ConvertFrom-SID
```

TESTLAB\WINDOWS2$
TESTLAB\harmj0y
BUILTIN\Distributed COM Users

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108 -Credential $Cred

TESTLAB\harmj0y

## PARAMETERS

### -ObjectSid
Specifies one or more SIDs to convert.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: SID

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

Accepts one or more SID strings on the pipeline.

## OUTPUTS

### String

The converted DOMAIN\username.

## NOTES

## RELATED LINKS

