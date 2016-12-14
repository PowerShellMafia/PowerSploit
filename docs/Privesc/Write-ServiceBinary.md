# Write-ServiceBinary

## SYNOPSIS
Patches in the specified command to a pre-compiled C# service executable and
writes the binary out to the specified ServicePath location.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Write-ServiceBinary [-Name] <String> [-UserName <String>] [-Password <String>] [-LocalGroup <String>]
 [-Credential <PSCredential>] [-Command <String>] [-Path <String>]
```

## DESCRIPTION
Takes a pre-compiled C# service binary and patches in the appropriate commands needed
for service abuse.
If a -UserName/-Password or -Credential is specified, the command
patched in creates a local user and adds them to the specified -LocalGroup, otherwise
the specified -Command is patched in.
The binary is then written out to the specified
-ServicePath.
Either -Name must be specified for the service, or a proper object from
Get-Service must be passed on the pipeline in order to patch in the appropriate service
name the binary will be running under.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Write-ServiceBinary -Name VulnSVC
```

Writes a service binary to service.exe in the local directory for VulnSVC that
adds a local Administrator (john/Password123!).

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Service VulnSVC | Write-ServiceBinary
```

Writes a service binary to service.exe in the local directory for VulnSVC that
adds a local Administrator (john/Password123!).

### -------------------------- EXAMPLE 3 --------------------------
```
Write-ServiceBinary -Name VulnSVC -UserName 'TESTLAB\john'
```

Writes a service binary to service.exe in the local directory for VulnSVC that adds
TESTLAB\john to the Administrators local group.

### -------------------------- EXAMPLE 4 --------------------------
```
Write-ServiceBinary -Name VulnSVC -UserName backdoor -Password Password123!
```

Writes a service binary to service.exe in the local directory for VulnSVC that
adds a local Administrator (backdoor/Password123!).

### -------------------------- EXAMPLE 5 --------------------------
```
Write-ServiceBinary -Name VulnSVC -Command "net ..."
```

Writes a service binary to service.exe in the local directory for VulnSVC that
executes a custom command.

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

### -Path
Path to write the binary out to, defaults to 'service.exe' in the local directory.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: "$(Convert-Path .)\service.exe"
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### PowerUp.ServiceBinary

## NOTES

## RELATED LINKS

