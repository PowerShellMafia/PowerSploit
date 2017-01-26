# Find-AVSignature

## SYNOPSIS
Locate tiny AV signatures.

PowerSploit Function: Find-AVSignature  
Authors: Chris Campbell (@obscuresec) & Matt Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Find-AVSignature [-StartByte] <UInt32> [-EndByte] <String> [-Interval] <UInt32> [[-Path] <String>]
 [[-OutPath] <String>] [[-BufferLen] <UInt32>] [-Force]
```

## DESCRIPTION
Locates single Byte AV signatures utilizing the same method as DSplit from "class101" on heapoverflow.com.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Find-AVSignature -Startbyte 0 -Endbyte max -Interval 10000 -Path c:\test\exempt\nc.exe
```

Find-AVSignature -StartByte 10000 -EndByte 20000 -Interval 1000 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run2 -Verbose
Find-AVSignature -StartByte 16000 -EndByte 17000 -Interval 100 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run3 -Verbose
Find-AVSignature -StartByte 16800 -EndByte 16900 -Interval 10 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run4 -Verbose
Find-AVSignature -StartByte 16890 -EndByte 16900 -Interval 1 -Path C:\test\exempt\nc.exe -OutPath c:\test\output\run5 -Verbose

## PARAMETERS

### -StartByte
Specifies the first byte to begin splitting on.

```yaml
Type: UInt32
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -EndByte
Specifies the last byte to split on.

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

### -Interval
Specifies the interval size to split with.

```yaml
Type: UInt32
Parameter Sets: (All)
Aliases: 

Required: True
Position: 3
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
Specifies the path to the binary you want tested.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 4
Default value: ($pwd.path)
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutPath
Optionally specifies the directory to write the binaries to.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 5
Default value: ($pwd)
Accept pipeline input: False
Accept wildcard characters: False
```

### -BufferLen
Specifies the length of the file read buffer . 
Defaults to 64KB.

```yaml
Type: UInt32
Parameter Sets: (All)
Aliases: 

Required: False
Position: 6
Default value: 65536
Accept pipeline input: False
Accept wildcard characters: False
```

### -Force
Forces the script to continue without confirmation.

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
Several of the versions of "DSplit.exe" available on the internet contain malware.

## RELATED LINKS

[http://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html
https://github.com/mattifestation/PowerSploit
http://www.exploit-monday.com/
http://heapoverflow.com/f0rums/project.php?issueid=34&filter=changes&page=2](http://obscuresecurity.blogspot.com/2012/12/finding-simple-av-signatures-with.html
https://github.com/mattifestation/PowerSploit
http://www.exploit-monday.com/
http://heapoverflow.com/f0rums/project.php?issueid=34&filter=changes&page=2)

