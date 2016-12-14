# Invoke-WScriptUACBypass

## SYNOPSIS
Performs the bypass UAC attack by abusing the lack of an embedded manifest in wscript.exe.

Author: Matt Nelson (@enigma0x3), Will Schroeder (@harmj0y), Vozzie  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Invoke-WScriptUACBypass [-Command] <String> [-WindowStyle <String>]
```

## DESCRIPTION
Drops wscript.exe and a custom manifest into C:\Windows and then proceeds to execute
VBScript using the wscript executable with the new manifest.
The VBScript executed by
C:\Windows\wscript.exe will run elevated.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
"
```

Launches the specified PowerShell encoded command in high-integrity.

### -------------------------- EXAMPLE 2 --------------------------
```
Invoke-WScriptUACBypass -Command cmd.exe -WindowStyle 'Visible'
```

Spawns a high integrity cmd.exe.

## PARAMETERS

### -Command
The shell command you want wscript.exe to run elevated.

```yaml
Type: String
Parameter Sets: (All)
Aliases: CMD

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -WindowStyle
Whether to display or hide the window for the executed '-Command X'.
Accepted values are 'Hidden' and 'Normal'/'Visible.
Default is 'Hidden'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Hidden
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES

## RELATED LINKS

[http://seclist.us/uac-bypass-vulnerability-in-the-windows-script-host.html
https://github.com/Vozzie/uacscript
https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-WScriptBypassUAC.ps1](http://seclist.us/uac-bypass-vulnerability-in-the-windows-script-host.html
https://github.com/Vozzie/uacscript
https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-WScriptBypassUAC.ps1)

