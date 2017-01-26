# Get-System

## SYNOPSIS
GetSystem functionality inspired by Meterpreter's getsystem.
'NamedPipe' impersonation doesn't need SeDebugPrivilege but does create
a service, 'Token' duplications a SYSTEM token but needs SeDebugPrivilege.
NOTE: if running PowerShell 2.0, start powershell.exe with '-STA' to ensure
token duplication works correctly.

PowerSploit Function: Get-System
Author: @harmj0y, @mattifestation
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

## SYNTAX

### NamedPipe (Default)
```
Get-System [-Technique <String>] [-ServiceName <String>] [-PipeName <String>]
```

### Token
```
Get-System [-Technique <String>]
```

### RevToSelf
```
Get-System [-RevToSelf]
```

### WhoAmI
```
Get-System [-WhoAmI]
```

## DESCRIPTION
{{Fill in the Description}}

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-System
```

Uses named impersonate to elevate the current thread token to SYSTEM.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-System -ServiceName 'PrivescSvc' -PipeName 'secret'
```

Uses named impersonate to elevate the current thread token to SYSTEM
with a custom service and pipe name.

### -------------------------- EXAMPLE 3 --------------------------
```
Get-System -Technique Token
```

Uses token duplication to elevate the current thread token to SYSTEM.

### -------------------------- EXAMPLE 4 --------------------------
```
Get-System -WhoAmI
```

Displays the credentials for the current thread.

### -------------------------- EXAMPLE 5 --------------------------
```
Get-System -RevToSelf
```

Reverts the current thread privileges.

## PARAMETERS

### -Technique
The technique to use, 'NamedPipe' or 'Token'.

```yaml
Type: String
Parameter Sets: NamedPipe, Token
Aliases: 

Required: False
Position: Named
Default value: NamedPipe
Accept pipeline input: False
Accept wildcard characters: False
```

### -ServiceName
The name of the service used with named pipe impersonation, defaults to 'TestSVC'.

```yaml
Type: String
Parameter Sets: NamedPipe
Aliases: 

Required: False
Position: Named
Default value: TestSVC
Accept pipeline input: False
Accept wildcard characters: False
```

### -PipeName
The name of the named pipe used with named pipe impersonation, defaults to 'TestSVC'.

```yaml
Type: String
Parameter Sets: NamedPipe
Aliases: 

Required: False
Position: Named
Default value: TestSVC
Accept pipeline input: False
Accept wildcard characters: False
```

### -RevToSelf
Reverts the current thread privileges.

```yaml
Type: SwitchParameter
Parameter Sets: RevToSelf
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhoAmI
Switch.
Display the credentials for the current PowerShell thread.

```yaml
Type: SwitchParameter
Parameter Sets: WhoAmI
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[https://github.com/rapid7/meterpreter/blob/2a891a79001fc43cb25475cc43bced9449e7dc37/source/extensions/priv/server/elevate/namedpipe.c
https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot
http://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/](https://github.com/rapid7/meterpreter/blob/2a891a79001fc43cb25475cc43bced9449e7dc37/source/extensions/priv/server/elevate/namedpipe.c
https://github.com/obscuresec/shmoocon/blob/master/Invoke-TwitterBot
http://blog.cobaltstrike.com/2014/04/02/what-happens-when-i-type-getsystem/
http://clymb3r.wordpress.com/2013/11/03/powershell-and-token-impersonation/)

