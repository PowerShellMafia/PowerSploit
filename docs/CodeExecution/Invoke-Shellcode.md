# Invoke-Shellcode

## SYNOPSIS
Inject shellcode into the process ID of your choosing or within the context of the running PowerShell process.

PowerSploit Function: Invoke-Shellcode  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Invoke-Shellcode [-ProcessID <UInt16>] [-Shellcode <Byte[]>] [-Force]
```

## DESCRIPTION
Portions of this project was based upon syringe.c v1.2 written by Spencer McIntyre

PowerShell expects shellcode to be in the form 0xXX,0xXX,0xXX.
To generate your shellcode in this form, you can use this command from within Backtrack (Thanks, Matt and g0tm1lk):

msfpayload windows/exec CMD="cmd /k calc" EXITFUNC=thread C | sed '1,6d;s/\[";\]//g;s/\\\\/,0/g' | tr -d '\n' | cut -c2-

Make sure to specify 'thread' for your exit process.
Also, don't bother encoding your shellcode.
It's entirely unnecessary.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Invoke-Shellcode -ProcessId 4274
```

Description
-----------
Inject shellcode into process ID 4274.

### -------------------------- EXAMPLE 2 --------------------------
```
Invoke-Shellcode
```

Description
-----------
Inject shellcode into the running instance of PowerShell.

### -------------------------- EXAMPLE 3 --------------------------
```
Invoke-Shellcode -Shellcode @(0x90,0x90,0xC3)
```

Description
-----------
Overrides the shellcode included in the script with custom shellcode - 0x90 (NOP), 0x90 (NOP), 0xC3 (RET)
Warning: This script has no way to validate that your shellcode is 32 vs.
64-bit!

## PARAMETERS

### -ProcessID
Process ID of the process you want to inject shellcode into.

```yaml
Type: UInt16
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Shellcode
Specifies an optional shellcode passed in as a byte array

```yaml
Type: Byte[]
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force
Injects shellcode without prompting for confirmation.
By default, Invoke-Shellcode prompts for confirmation before performing any malicious act.

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

## RELATED LINKS

