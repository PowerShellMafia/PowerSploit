# Find-ProcessDLLHijack

## SYNOPSIS
Finds all DLL hijack locations for currently running processes.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Find-ProcessDLLHijack [[-Name] <String[]>] [-ExcludeWindows] [-ExcludeProgramFiles] [-ExcludeOwned]
```

## DESCRIPTION
Enumerates all currently running processes with Get-Process (or accepts an
input process object from Get-Process) and enumerates the loaded modules for each.
All loaded module name exists outside of the process binary base path, as those
are DLL load-order hijack candidates.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-ProcessDLLHijack
```

Finds possible hijackable DLL locations for all processes.

### -------------------------- EXAMPLE 2 --------------------------
```
Get-Process VulnProcess | Find-ProcessDLLHijack
```

Finds possible hijackable DLL locations for the 'VulnProcess' processes.

### -------------------------- EXAMPLE 3 --------------------------
```
Find-ProcessDLLHijack -ExcludeWindows -ExcludeProgramFiles
```

Finds possible hijackable DLL locations not in C:\Windows\* and
not in C:\Program Files\* or C:\Program Files (x86)\*

### -------------------------- EXAMPLE 4 --------------------------
```
Find-ProcessDLLHijack -ExcludeOwned
```

Finds possible hijackable DLL location for processes not owned by the
current user.

## PARAMETERS

### -Name
The name of a process to enumerate for possible DLL path hijack opportunities.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: ProcessName

Required: False
Position: 1
Default value: $(Get-Process | Select-Object -Expand Name)
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ExcludeWindows
Exclude paths from C:\Windows\* instead of just C:\Windows\System32\*

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

### -ExcludeProgramFiles
Exclude paths from C:\Program Files\* and C:\Program Files (x86)\*

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

### -ExcludeOwned
Exclude processes the current user owns.

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

### PowerUp.HijackableDLL.Process

## NOTES

## RELATED LINKS

[https://www.mandiant.com/blog/malware-persistence-windows-registry/](https://www.mandiant.com/blog/malware-persistence-windows-registry/)

