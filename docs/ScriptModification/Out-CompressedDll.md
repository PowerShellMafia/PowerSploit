# Out-CompressedDll

## SYNOPSIS
Compresses, Base-64 encodes, and outputs generated code to load a managed dll in memory.

PowerSploit Function: Out-CompressedDll  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Out-CompressedDll [-FilePath] <String>
```

## DESCRIPTION
Out-CompressedDll outputs code that loads a compressed representation of a managed dll in memory as a byte array.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Out-CompressedDll -FilePath evil.dll
```

Description
-----------
Compresses, base64 encodes, and outputs the code required to load evil.dll in memory.

## PARAMETERS

### -FilePath
Specifies the path to a managed executable.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES
Only pure MSIL-based dlls can be loaded using this technique.
Native or IJW ('it just works' - mixed-mode) dlls will not load.

## RELATED LINKS

[http://www.exploit-monday.com/2012/12/in-memory-dll-loading.html](http://www.exploit-monday.com/2012/12/in-memory-dll-loading.html)

