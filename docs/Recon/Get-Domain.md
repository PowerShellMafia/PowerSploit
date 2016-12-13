# Get-Domain

## SYNOPSIS
Returns the domain object for the current (or specified) domain.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-Domain [[-Domain] <String>] [-Credential <PSCredential>]
```

## DESCRIPTION
Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
domain or the domain specified with -Domain X.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-Domain -Domain testlab.local
```

### -------------------------- EXAMPLE 2 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-Domain -Credential $Cred

## PARAMETERS

### -Domain
Specifies the domain name to query for, defaults to the current domain.

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

### System.DirectoryServices.ActiveDirectory.Domain

A complex .NET domain object.

## NOTES

## RELATED LINKS

[http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG](http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG)

