# Remove-Comment

## SYNOPSIS
Strips comments and extra whitespace from a script.

PowerSploit Function: Remove-Comment  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

### FilePath (Default)
```
Remove-Comment [-Path] <String>
```

### ScriptBlock
```
Remove-Comment [-ScriptBlock] <ScriptBlock>
```

## DESCRIPTION
Remove-Comment strips out comments and unnecessary whitespace from a script.
This is best used in conjunction with Out-EncodedCommand when the size of the script to be encoded might be too big.

A major portion of this code was taken from the Lee Holmes' Show-ColorizedContent script.
You rock, Lee!

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$Stripped = Remove-Comment -Path .\ScriptWithComments.ps1
```

### -------------------------- EXAMPLE 2 --------------------------
```
Remove-Comment -ScriptBlock {
```

### This is my awesome script.
My documentation is beyond reproach!
      Write-Host 'Hello, World!' ### Write 'Hello, World' to the host
### End script awesomeness
}

Write-Host 'Hello, World!'

### -------------------------- EXAMPLE 3 --------------------------
```
Remove-Comment -Path Inject-Shellcode.ps1 | Out-EncodedCommand
```

Description
-----------
Removes extraneous whitespace and comments from Inject-Shellcode (which is notoriously large) and pipes the output to Out-EncodedCommand.

## PARAMETERS

### -Path
Specifies the path to your script.

```yaml
Type: String
Parameter Sets: FilePath
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ScriptBlock
Specifies a scriptblock containing your script.

```yaml
Type: ScriptBlock
Parameter Sets: ScriptBlock
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

## INPUTS

### System.String, System.Management.Automation.ScriptBlock

Accepts either a string containing the path to a script or a scriptblock.

## OUTPUTS

### System.Management.Automation.ScriptBlock

Remove-Comment returns a scriptblock. Call the ToString method to convert a scriptblock to a string, if desired.

## NOTES

## RELATED LINKS

[http://www.exploit-monday.com
http://www.leeholmes.com/blog/2007/11/07/syntax-highlighting-in-powershell/]()

