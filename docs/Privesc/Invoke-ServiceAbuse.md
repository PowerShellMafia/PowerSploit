# Invoke-ServiceAbuse

## SYNOPSIS
Abuses a function the current user has configuration rights on in order
to add a local administrator or execute a custom command.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ServiceDetail, Set-ServiceBinaryPath

## SYNTAX

```
Invoke-ServiceAbuse [-Name] <String[]> [-UserName <String>] [-Password <String>] [-LocalGroup <String>]
 [-Credential <PSCredential>] [-Command <String>] [-Force]
```

## DESCRIPTION
Takes a service Name or a ServiceProcess.ServiceController on the pipeline that the current
user has configuration modification rights on and executes a series of automated actions to
execute commands as SYSTEM.
First, the service is enabled if it was set as disabled and the
original service binary path and configuration state are preserved.
Then the service is stopped
and the Set-ServiceBinaryPath function is used to set the binary (binPath) for the service to a
series of commands, the service is started, stopped, and the next command is configured.
After
completion, the original service configuration is restored and a custom object is returned
that captures the service abused and commands run.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Invoke-ServiceAbuse -Name VulnSVC
```

Abuses service 'VulnSVC' to add a localuser "john" with password
"Password123!
to the  machine and local administrator group

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Service VulnSVC | Invoke-ServiceAbuse
```

Abuses service 'VulnSVC' to add a localuser "john" with password
"Password123!
to the  machine and local administrator group

### -------------------------- EXAMPLE 3 --------------------------
```
Invoke-ServiceAbuse -Name VulnSVC -UserName "TESTLAB\john"
```

Abuses service 'VulnSVC' to add a the domain user TESTLAB\john to the
local adminisrtators group.

### -------------------------- EXAMPLE 4 --------------------------
```
Invoke-ServiceAbuse -Name VulnSVC -UserName backdoor -Password password -LocalGroup "Power Users"
```

Abuses service 'VulnSVC' to add a localuser "backdoor" with password
"password" to the  machine and local "Power Users" group

### -------------------------- EXAMPLE 5 --------------------------
```
Invoke-ServiceAbuse -Name VulnSVC -Command "net ..."
```

Abuses service 'VulnSVC' to execute a custom command.

## PARAMETERS

### -Name
An array of one or more service names to abuse.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: ServiceName

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -UserName
The \[domain\\\]username to add.
If not given, it defaults to "john".
Domain users are not created, only added to the specified localgroup.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: John
Accept pipeline input: False
Accept wildcard characters: False
```

### -Password
The password to set for the added user.
If not given, it defaults to "Password123!"

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Password123!
Accept pipeline input: False
Accept wildcard characters: False
```

### -LocalGroup
Local group name to add the user to (default of 'Administrators').

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Administrators
Accept pipeline input: False
Accept wildcard characters: False
```

### -Credential
A \[Management.Automation.PSCredential\] object specifying the user/password to add.

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

### -Command
Custom command to execute instead of user creation.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force
Switch.
Force service stopping, even if other services are dependent.

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

### PowerUp.AbusedService

## NOTES

## RELATED LINKS

