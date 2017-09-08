# Get-DomainSID

## SYNOPSIS
Returns the SID for the current domain or the specified domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-DomainComputer

## SYNTAX

```
Get-DomainSID [[-Domain] <String>] [[-Server] <String>] [[-Credential] <PSCredential>]
```

## DESCRIPTION
Returns the SID for the current domain or the specified domain by executing
Get-DomainComputer with the -LDAPFilter set to (userAccountControl:1.2.840.113556.1.4.803:=8192)
to search for domain controllers through LDAP.
The SID of the returned domain controller
is then extracted.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainSID
```

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainSID -Domain testlab.local
```

### -------------------------- EXAMPLE 3 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainSID -Credential $Cred

## PARAMETERS

### -Domain
Specifies the domain to use for the query, defaults to the current domain.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 1
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
Position: 2
Default value: None
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
Position: 3
Default value: [Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### String

A string representing the specified domain SID.

## NOTES

## RELATED LINKS

