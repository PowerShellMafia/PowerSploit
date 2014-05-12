function Register-ProcessModuleTrace
{
<#
.SYNOPSIS

    Starts a trace of loaded process modules

    PowerSploit Function: Register-ProcessModuleTrace
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.OUTPUTS

    System.Management.Automation.PSEventJob

    If desired, you can manipulate the event returned with the *-Event cmdlets.

.LINK

    http://www.exploit-monday.com/
#>

    [CmdletBinding()] Param ()

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))
    {
        throw 'You must run this cmdlet from an elevated PowerShell session.'
    }

    $ModuleLoadedAction = {
        $Event = $EventArgs.NewEvent

        $ModuleInfo = @{
            TimeCreated = [DateTime]::FromFileTime($Event.TIME_CREATED)
            ProcessId = $Event.ProcessId
            FileName = $Event.FileName
            ImageBase = $Event.ImageBase
            ImageSize = $Event.ImageSize
        }

        $ModuleObject = New-Object PSObject -Property $ModuleInfo
        $ModuleObject.PSObject.TypeNames[0] = 'LOADED_MODULE'

        $ModuleObject
    }

    Register-WmiEvent 'Win32_ModuleLoadTrace' -SourceIdentifier 'ModuleLoaded' -Action $ModuleLoadedAction
}

function Get-ProcessModuleTrace
{
<#
.SYNOPSIS

    Displays the process modules that have been loaded since the call to Register-ProcessModuleTrace

    PowerSploit Function: Get-ProcessModuleTrace
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: Register-ProcessModuleTrace
    Optional Dependencies: None

.OUTPUTS

    PSObject

.LINK

    http://www.exploit-monday.com/
#>

    $Events = Get-EventSubscriber -SourceIdentifier 'ModuleLoaded' -ErrorVariable NoEventRegistered -ErrorAction SilentlyContinue

    if ($NoEventRegistered)
    {
        throw 'You must execute Register-ProcessModuleTrace before you can retrieve a loaded module list'
    }

    $Events.Action.Output
}

function Unregister-ProcessModuleTrace
{
<#
.SYNOPSIS

    Stops the running process module trace

    PowerSploit Function: Unregister-ProcessModuleTrace
    Author: Matthew Graeber (@mattifestation)
    License: BSD 3-Clause
    Required Dependencies: Register-ProcessModuleTrace
    Optional Dependencies: None

.LINK

    http://www.exploit-monday.com/
#>

    Unregister-Event -SourceIdentifier 'ModuleLoaded'
}
