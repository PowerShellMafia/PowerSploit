# Invoke-DllInjection

## SYNOPSIS
Injects a Dll into the process ID of your choosing.

PowerSploit Function: Invoke-DllInjection  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Invoke-DllInjection [-ProcessID] <Int32> [-Dll] <String>
```

## DESCRIPTION
Invoke-DllInjection injects a Dll into an arbitrary process.
It does this by using VirtualAllocEx to allocate memory the size of the
DLL in the remote process, writing the names of the DLL to load into the
remote process spacing using WriteProcessMemory, and then using RtlCreateUserThread
to invoke LoadLibraryA in the context of the remote process.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Invoke-DllInjection -ProcessID 4274 -Dll evil.dll
```

Description
-----------
Inject 'evil.dll' into process ID 4274.

## PARAMETERS

### -ProcessID
Process ID of the process you want to inject a Dll into.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Dll
Name of the dll to inject.
This can be an absolute or relative path.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES
Use the '-Verbose' option to print detailed information.

## RELATED LINKS

[http://www.exploit-monday.com](http://www.exploit-monday.com)

