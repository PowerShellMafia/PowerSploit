# Invoke-RevertToSelf

## SYNOPSIS
Reverts any token impersonation.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect

## SYNTAX

```
Invoke-RevertToSelf [[-TokenHandle] <IntPtr>]
```

## DESCRIPTION
This function uses RevertToSelf() to revert any impersonated tokens.
If -TokenHandle is passed (the token handle returned by Invoke-UserImpersonation),
CloseHandle() is used to close the opened handle.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$Token = Invoke-UserImpersonation -Credential $Cred
Invoke-RevertToSelf -TokenHandle $Token

## PARAMETERS

### -TokenHandle
An optional IntPtr TokenHandle returned by Invoke-UserImpersonation.

```yaml
Type: IntPtr
Parameter Sets: (All)
Aliases: 

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

