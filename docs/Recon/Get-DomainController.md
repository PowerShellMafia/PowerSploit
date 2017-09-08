# Get-DomainController

## SYNOPSIS
Return the domain controllers for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer, Get-Domain

## SYNTAX

```
Get-DomainController [[-Domain] <String>] [-Server <String>] [-LDAP] [-Credential <PSCredential>]
```

## DESCRIPTION
Enumerates the domain controllers for the current or specified domain.
By default built in .NET methods are used.
The -LDAP switch uses Get-DomainComputer
to search for domain controllers.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainController -Domain 'test.local'
```

Determine the domain controllers for 'test.local'.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainController -Domain 'test.local' -LDAP
```

Determine the domain controllers for 'test.local' using LDAP queries.

### -------------------------- EXAMPLE 3 --------------------------
```
'test.local' | Get-DomainController
```

Determine the domain controllers for 'test.local'.

### -------------------------- EXAMPLE 4 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainController -Credential $Cred

## PARAMETERS

### -Domain
The domain to query for domain controllers, defaults to the current domain.

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

### -LDAP
Switch.
Use LDAP queries to determine the domain controllers instead of built in .NET methods.

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

### PowerView.Computer

Outputs custom PSObjects with details about the enumerated domain controller if -LDAP is specified.

System.DirectoryServices.ActiveDirectory.DomainController

If -LDAP isn't specified.

## NOTES

## RELATED LINKS

