# Export-PowerViewCSV

## SYNOPSIS
Converts objects into a series of comma-separated (CSV) strings and saves the
strings in a CSV file in a thread-safe manner.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
Export-PowerViewCSV -InputObject <PSObject[]> [-Path] <String> [[-Delimiter] <Char>] [-Append]
```

## DESCRIPTION
This helper exports an -InputObject to a .csv in a thread-safe manner
using a mutex.
This is so the various multi-threaded functions in
PowerView has a thread-safe way to export output to the same file.
Uses .NET IO.FileStream/IO.StreamWriter objects for speed.

Originally based on Dmitry Sotnikov's Export-CSV code: http://poshcode.org/1590

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Get-DomainUser | Export-PowerViewCSV -Path "users.csv"
```

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainUser | Export-PowerViewCSV -Path "users.csv" -Append -Delimiter '|'
```

## PARAMETERS

### -InputObject
Specifies the objects to export as CSV strings.

```yaml
Type: PSObject[]
Parameter Sets: (All)
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -Path
Specifies the path to the CSV output file.

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

### -Delimiter
Specifies a delimiter to separate the property values.
The default is a comma (,)

```yaml
Type: Char
Parameter Sets: (All)
Aliases: 

Required: False
Position: 3
Default value: ,
Accept pipeline input: False
Accept wildcard characters: False
```

### -Append
Indicates that this cmdlet adds the CSV output to the end of the specified file.
Without this parameter, Export-PowerViewCSV replaces the file contents without warning.

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

### PSObject

Accepts one or more PSObjects on the pipeline.

## OUTPUTS

## NOTES

## RELATED LINKS

[http://poshcode.org/1590
http://dmitrysotnikov.wordpress.com/2010/01/19/Export-Csv-append/](http://poshcode.org/1590
http://dmitrysotnikov.wordpress.com/2010/01/19/Export-Csv-append/)

