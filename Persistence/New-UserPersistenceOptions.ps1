function New-UserPersistenceOptions
{
<#
.SYNOPSIS

    Configure user-level persistence options for the Add-Persistence function.

    PowerSploit Function: New-UserPersistenceOptions
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None
 
.DESCRIPTION

    New-UserPersistenceOptions allows for the configuration of elevated persistence options. The output of this function is a required parameter of Add-Persistence. Available persitence options in order of stealth are the following: scheduled task, registry.

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

    C:\PS> $UserOptions = New-UserPersistenceOptions -Registry -AtLogon

.EXAMPLE

    C:\PS> $UserOptions = New-UserPersistenceOptions -ScheduledTask -OnIdle

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
    $PersistenceOptions.PSObject.TypeNames[0] = 'PowerSploit.Persistence.UserPersistenceOptions'

    Write-Output $PersistenceOptions
}