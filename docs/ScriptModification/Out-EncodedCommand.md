# Out-EncodedCommand

## SYNOPSIS
Compresses, Base-64 encodes, and generates command-line output for a PowerShell payload script.

PowerSploit Function: Out-EncodedCommand  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

### FilePath (Default)
```
Out-EncodedCommand [[-Path] <String>] [-NoExit] [-NoProfile] [-NonInteractive] [-Wow64] [-WindowStyle <String>]
 [-EncodedOutput]
```

### ScriptBlock
```
Out-EncodedCommand [[-ScriptBlock] <ScriptBlock>] [-NoExit] [-NoProfile] [-NonInteractive] [-Wow64]
 [-WindowStyle <String>] [-EncodedOutput]
```

## DESCRIPTION
Out-EncodedCommand prepares a PowerShell script such that it can be pasted into a command prompt.
The scenario for using this tool is the following: You compromise a machine, have a shell and want to execute a PowerShell script as a payload.
This technique eliminates the need for an interactive PowerShell 'shell' and it bypasses any PowerShell execution policies.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Out-EncodedCommand -ScriptBlock {Write-Host 'hello, world!'}
```

powershell -C sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream(\[IO.MemoryStream\]\[Convert\]::FromBase64String('Cy/KLEnV9cgvLlFQz0jNycnXUSjPL8pJUVQHAA=='),\[IO.Compression.CompressionMode\]::Decompress)),\[Text.Encoding\]::ASCII)).ReadToEnd()

### -------------------------- EXAMPLE 2 --------------------------
```
Out-EncodedCommand -Path C:\EvilPayload.ps1 -NonInteractive -NoProfile -WindowStyle Hidden -EncodedOutput
```

powershell -NoP -NonI -W Hidden -E cwBhAGwAIABhACAATgBlAHcALQBPAGIAagBlAGMAdAA7AGkAZQB4ACgAYQAgAEkATwAuAFMAdAByAGUAYQBtAFIAZQBhAGQAZQByACgAKABhACAASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4ARABlAGYAbABhAHQAZQBTAHQAcgBlAGEAbQAoAFsASQBPAC4ATQBlAG0AbwByAHkAUwB0AHIAZQBhAG0AXQBbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcATABjAGkAeABDAHMASQB3AEUAQQBEAFEAWAAzAEUASQBWAEkAYwBtAEwAaQA1AEsAawBGAEsARQA2AGwAQgBCAFIAWABDADgAaABLAE8ATgBwAEwAawBRAEwANAAzACsAdgBRAGgAdQBqAHkAZABBADkAMQBqAHEAcwAzAG0AaQA1AFUAWABkADAAdgBUAG4ATQBUAEMAbQBnAEgAeAA0AFIAMAA4AEoAawAyAHgAaQA5AE0ANABDAE8AdwBvADcAQQBmAEwAdQBYAHMANQA0ADEATwBLAFcATQB2ADYAaQBoADkAawBOAHcATABpAHMAUgB1AGEANABWAGEAcQBVAEkAagArAFUATwBSAHUAVQBsAGkAWgBWAGcATwAyADQAbgB6AFYAMQB3ACsAWgA2AGUAbAB5ADYAWgBsADIAdAB2AGcAPQA9ACcAKQAsAFsASQBPAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAC4AQwBvAG0AcAByAGUAcwBzAGkAbwBuAE0AbwBkAGUAXQA6ADoARABlAGMAbwBtAHAAcgBlAHMAcwApACkALABbAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA=

Description
-----------
Execute the above payload for the lulz.
\>D

## PARAMETERS

### -ScriptBlock
Specifies a scriptblock containing your payload.

```yaml
Type: ScriptBlock
Parameter Sets: ScriptBlock
Aliases: 

Required: False
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Path
Specifies the path to your payload.

```yaml
Type: String
Parameter Sets: FilePath
Aliases: 

Required: False
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -NoExit
Outputs the option to not exit after running startup commands.

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

### -NoProfile
Outputs the option to not load the Windows PowerShell profile.

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

### -NonInteractive
Outputs the option to not present an interactive prompt to the user.

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

### -Wow64
Calls the x86 (Wow64) version of PowerShell on x86_64 Windows installations.

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

### -WindowStyle
Outputs the option to set the window style to Normal, Minimized, Maximized or Hidden.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EncodedOutput
Base-64 encodes the entirety of the output.
This is usually unnecessary and effectively doubles the size of the output.
This option is only for those who are extra paranoid.

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

## NOTES
This cmdlet was inspired by the createcmd.ps1 script introduced during Dave Kennedy and Josh Kelley's talk, "PowerShell...OMFG" (https://www.trustedsec.com/files/PowerShell_PoC.zip)

## RELATED LINKS

[http://www.exploit-monday.com](http://www.exploit-monday.com)

