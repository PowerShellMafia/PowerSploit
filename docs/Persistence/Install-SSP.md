# Install-SSP

## SYNOPSIS
Installs a security support provider (SSP) dll.

Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Install-SSP [[-Path] <String>]
```

## DESCRIPTION
Install-SSP installs an SSP dll.
Installation involves copying the dll to
%windir%\System32 and adding the name of the dll to
HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Install-SSP -Path .\mimilib.dll
```

## PARAMETERS

### -Path
{{Fill Path Description}}

```yaml
Type: String
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
The SSP dll must match the OS architecture.
i.e.
You must have a 64-bit SSP dll
if you are running a 64-bit OS.
In order for the SSP dll to be loaded properly
into lsass, the dll must export SpLsaModeInitialize.

## RELATED LINKS

