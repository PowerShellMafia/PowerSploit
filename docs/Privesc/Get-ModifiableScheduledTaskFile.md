# Get-ModifiableScheduledTaskFile

## SYNOPSIS
Returns scheduled tasks where the current user can modify any file
in the associated task action string.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-ModifiablePath

## SYNTAX

```
Get-ModifiableScheduledTaskFile
```

## DESCRIPTION
Enumerates all scheduled tasks by recursively listing "$($ENV:windir)\System32\Tasks"
and parses the XML specification for each task, extracting the command triggers.
Each trigger string is filtered through Get-ModifiablePath, returning any file/config
locations in the found path strings that the current user can modify.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ModifiableScheduledTaskFile
```

Return scheduled tasks with modifiable command strings.

## PARAMETERS

## INPUTS

## OUTPUTS

### PowerUp.ModifiableScheduledTaskFile

Custom PSObject containing results.

## NOTES

## RELATED LINKS

