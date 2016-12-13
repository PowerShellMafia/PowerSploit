# Invoke-UserImpersonation

## SYNOPSIS
Creates a new "runas /netonly" type logon and impersonates the token.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: PSReflect

## SYNTAX

### Credential (Default)
```
Invoke-UserImpersonation -Credential <PSCredential> [-Quiet]
```

### TokenHandle
```
Invoke-UserImpersonation -TokenHandle <IntPtr> [-Quiet]
```

## DESCRIPTION
This function uses LogonUser() with the LOGON32_LOGON_NEW_CREDENTIALS LogonType
to simulate "runas /netonly".
The resulting token is then impersonated with
ImpersonateLoggedOnUser() and the token handle is returned for later usage
with Invoke-RevertToSelf.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
```

$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred

## PARAMETERS

### -Credential
A \[Management.Automation.PSCredential\] object with alternate credentials
to impersonate in the current thread space.

```yaml
Type: PSCredential
Parameter Sets: Credential
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TokenHandle
An IntPtr TokenHandle returned by a previous Invoke-UserImpersonation.
If this is supplied, LogonUser() is skipped and only ImpersonateLoggedOnUser()
is executed.

```yaml
Type: IntPtr
Parameter Sets: TokenHandle
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Quiet
Suppress any warnings about STA vs MTA.

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

## INPUTS

## OUTPUTS

### IntPtr

The TokenHandle result from LogonUser.

## NOTES

## RELATED LINKS

