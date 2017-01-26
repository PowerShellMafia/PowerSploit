# Invoke-PrivescAudit

## SYNOPSIS
Executes all functions that check for various Windows privilege escalation opportunities.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Invoke-PrivescAudit [-HTMLReport]
```

## DESCRIPTION
Executes all functions that check for various Windows privilege escalation opportunities.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Invoke-PrivescAudit
```

Runs all escalation checks and outputs a status report for discovered issues.

### -------------------------- EXAMPLE 2 --------------------------
```
Invoke-PrivescAudit -HTMLReport
```

Runs all escalation checks and outputs a status report to SYSTEM.username.html
detailing any discovered issues.

## PARAMETERS

### -HTMLReport
Switch.
Write a HTML version of the report to SYSTEM.username.html.

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

### System.String

## NOTES

## RELATED LINKS

