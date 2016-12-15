# Get-ComputerDetail

## SYNOPSIS
This script is used to get useful information from a computer.

Function: Get-ComputerDetail  
Author: Joe Bialek, Twitter: @JosephBialek  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Get-ComputerDetail [-ToString]
```

## DESCRIPTION
This script is used to get useful information from a computer.
Currently, the script gets the following information:
-Explicit Credential Logons (Event ID 4648)
-Logon events (Event ID 4624)
-AppLocker logs to find what processes are created
-PowerShell logs to find PowerShell scripts which have been executed
-RDP Client Saved Servers, which indicates what servers the user typically RDP's in to

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-ComputerDetail
```

Gets information about the computer and outputs it as PowerShell objects.

Get-ComputerDetail -ToString
Gets information about the computer and outputs it as raw text.

## PARAMETERS

### -ToString
Switch: Outputs the data as text instead of objects, good if you are using this script through a backdoor.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: 

Required: False
Position: 1
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES
This script is useful for fingerprinting a server to see who connects to this server (from where), and where users on this server connect to.
You can also use it to find Powershell scripts and executables which are typically run, and then use this to backdoor those files.

## RELATED LINKS

[Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell](Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell)

