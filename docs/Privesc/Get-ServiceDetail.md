# Get-ServiceDetail

## SYNOPSIS
Returns detailed information about a specified service by querying the
WMI win32_service class for the specified service name.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Get-ServiceDetail [-Name] <String[]>
```

## DESCRIPTION
Takes an array of one or more service Names or ServiceProcess.ServiceController objedts on
the pipeline object returned by Get-Service, extracts out the service name, queries the
WMI win32_service class for the specified service for details like binPath, and outputs
everything.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ServiceDetail -Name VulnSVC
```

Gets detailed information about the 'VulnSVC' service.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Service VulnSVC | Get-ServiceDetail
```

Gets detailed information about the 'VulnSVC' service.

## PARAMETERS

### -Name
An array of one or more service names to query information for.

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

## INPUTS

## OUTPUTS

### System.Management.ManagementObject

## NOTES

## RELATED LINKS

