# Add-ServiceDacl

## SYNOPSIS
Adds a Dacl field to a service object returned by Get-Service.

Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: PSReflect

## SYNTAX

```
Add-ServiceDacl [-Name] <String[]>
```

## DESCRIPTION
Takes one or more ServiceProcess.ServiceController objects on the pipeline and adds a
Dacl field to each object.
It does this by opening a handle with ReadControl for the
service with using the GetServiceHandle Win32 API call and then uses
QueryServiceObjectSecurity to retrieve a copy of the security descriptor for the service.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-Service | Add-ServiceDacl
```

Add Dacls for every service the current user can read.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Service -Name VMTools | Add-ServiceDacl
```

Add the Dacl to the VMTools service object.

## PARAMETERS

### -Name
An array of one or more service names to add a service Dacl for.
Passable on the pipeline.

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

### ServiceProcess.ServiceController

## NOTES

## RELATED LINKS

[https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/](https://rohnspowershellblog.wordpress.com/2013/03/19/viewing-service-acls/)

