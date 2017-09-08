# Set-CriticalProcess

## SYNOPSIS
Causes your machine to blue screen upon exiting PowerShell.

PowerSploit Function: Set-CriticalProcess  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Set-CriticalProcess [-Force] [-ExitImmediately] [-WhatIf] [-Confirm]
```

## DESCRIPTION
{{Fill in the Description}}

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Set-CriticalProcess
```

### -------------------------- EXAMPLE 2 --------------------------
```
Set-CriticalProcess -ExitImmediately
```

### -------------------------- EXAMPLE 3 --------------------------
```
Set-CriticalProcess -Force -Verbose
```

## PARAMETERS

### -Force
Set the running PowerShell process as critical without asking for confirmation.

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

### -ExitImmediately
Immediately exit PowerShell after successfully marking the process as critical.

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

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

