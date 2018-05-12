# Install-ServiceBinary

## SYNOPSIS
Replaces the service binary for the specified service with one that executes
a specified command as SYSTEM.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ServiceDetail, Get-ModifiablePath, Write-ServiceBinary

## SYNTAX

```
Install-ServiceBinary [-Name] <String> [-UserName <String>] [-Password <String>] [-LocalGroup <String>]
 [-Credential <PSCredential>] [-Command <String>]
```

## DESCRIPTION
Takes a esrvice Name or a ServiceProcess.ServiceController on the pipeline where the
current user can  modify the associated service binary listed in the binPath.
Backs up
the original service binary to "OriginalService.exe.bak" in service binary location,
and then uses Write-ServiceBinary to create a C# service binary that either adds
a local administrator user or executes a custom command.
The new service binary is
replaced in the original service binary path, and a custom object is returned that
captures the original and new service binary configuration.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Install-ServiceBinary -Name VulnSVC
```

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that adds a local Administrator (john/Password123!).

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Service VulnSVC | Install-ServiceBinary
```

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that adds a local Administrator (john/Password123!).

### -------------------------- EXAMPLE 3 --------------------------
```
Install-ServiceBinary -Name VulnSVC -UserName 'TESTLAB\john'
```

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that adds TESTLAB\john to the Administrators local group.

### -------------------------- EXAMPLE 4 --------------------------
```
Install-ServiceBinary -Name VulnSVC -UserName backdoor -Password Password123!
```

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that adds a local Administrator (backdoor/Password123!).

### -------------------------- EXAMPLE 5 --------------------------
```
Install-ServiceBinary -Name VulnSVC -Command "net ..."
```

Backs up the original service binary to SERVICE_PATH.exe.bak and replaces the binary
for VulnSVC with one that executes a custom command.

## PARAMETERS

### -Name
The service name the EXE will be running under.

```yaml
Type: String
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

## INPUTS

## OUTPUTS

### PowerUp.ServiceBinary.Installed

## NOTES

## RELATED LINKS

