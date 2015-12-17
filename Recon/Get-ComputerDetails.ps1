function Get-ComputerDetails
{
<#
.SYNOPSIS

This script is used to get useful information from a computer.

Function: Get-ComputerDetails
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

This script is used to get useful information from a computer. Currently, the script gets the following information:
-Explicit Credential Logons (Event ID 4648)
-Logon events (Event ID 4624)
-AppLocker logs to find what processes are created
-PowerShell logs to find PowerShell scripts which have been executed
-RDP Client Saved Servers, which indicates what servers the user typically RDP's in to

.PARAMETER ToString

Switch: Outputs the data as text instead of objects, good if you are using this script through a backdoor.
	
.EXAMPLE

Get-ComputerDetails
Gets information about the computer and outputs it as PowerShell objects.

Get-ComputerDetails -ToString
Gets information about the computer and outputs it as raw text.

.NOTES
This script is useful for fingerprinting a server to see who connects to this server (from where), and where users on this server connect to. 
You can also use it to find Powershell scripts and executables which are typically run, and then use this to backdoor those files.

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell

#>

    Param(
        [Parameter(Position=0)]
        [Switch]
        $ToString
    )

    Set-StrictMode -Version 2



    $SecurityLog = Get-EventLog -LogName Security
    $Filtered4624 = Find-4624Logons $SecurityLog
    $Filtered4648 = Find-4648Logons $SecurityLog
    $AppLockerLogs = Find-AppLockerLogs
    $PSLogs = Find-PSScriptsInPSAppLog
    $RdpClientData = Find-RDPClientConnections

    if ($ToString)
    {
        Write-Output "Event ID 4624 (Logon):"
        Write-Output $Filtered4624.Values | Format-List
        Write-Output "Event ID 4648 (Explicit Credential Logon):"
        Write-Output $Filtered4648.Values | Format-List
        Write-Output "AppLocker Process Starts:"
        Write-Output $AppLockerLogs.Values | Format-List
        Write-Output "PowerShell Script Executions:"
        Write-Output $PSLogs.Values | Format-List
        Write-Output "RDP Client Data:"
        Write-Output $RdpClientData.Values | Format-List
    }
    else
    {
        $Properties = @{
            LogonEvent4624 = $Filtered4624.Values
            LogonEvent4648 = $Filtered4648.Values
            AppLockerProcessStart = $AppLockerLogs.Values
            PowerShellScriptStart = $PSLogs.Values
            RdpClientData = $RdpClientData.Values
        }

        $ReturnObj = New-Object PSObject -Property $Properties
        return $ReturnObj
    }
}


function Find-4648Logons
{
<#
.SYNOPSIS

Retrieve the unique 4648 logon events. This will often find cases where a user is using remote desktop to connect to another computer. It will give the 
the account that RDP was launched with and the account name of the account being used to connect to the remote computer. This is useful
for identifying normal authenticaiton patterns. Other actions that will trigger this include any runas action.

Function: Find-4648Logons
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Retrieve the unique 4648 logon events. This will often find cases where a user is using remote desktop to connect to another computer. It will give the 
the account that RDP was launched with and the account name of the account being used to connect to the remote computer. This is useful
for identifying normal authenticaiton patterns. Other actions that will trigger this include any runas action.

.EXAMPLE

Find-4648Logons
Gets the unique 4648 logon events.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    Param(
        $SecurityLog
    )

    $ExplicitLogons = $SecurityLog | Where {$_.InstanceID -eq 4648}
    $ReturnInfo = @{}

    foreach ($ExplicitLogon in $ExplicitLogons)
    {
        $Subject = $false
        $AccountWhosCredsUsed = $false
        $TargetServer = $false
        $SourceAccountName = ""
        $SourceAccountDomain = ""
        $TargetAccountName = ""
        $TargetAccountDomain = ""
        $TargetServer = ""
        foreach ($line in $ExplicitLogon.Message -split "\r\n")
        {
            if ($line -cmatch "^Subject:$")
            {
                $Subject = $true
            }
            elseif ($line -cmatch "^Account\sWhose\sCredentials\sWere\sUsed:$")
            {
                $Subject = $false
                $AccountWhosCredsUsed = $true
            }
            elseif ($line -cmatch "^Target\sServer:")
            {
                $AccountWhosCredsUsed = $false
                $TargetServer = $true
            }
            elseif ($Subject -eq $true)
            {
                if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
                {
                    $SourceAccountName = $Matches[1]
                }
                elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
                {
                    $SourceAccountDomain = $Matches[1]
                }
            }
            elseif ($AccountWhosCredsUsed -eq $true)
            {
                if ($line -cmatch "\s+Account\sName:\s+(\S.*)")
                {
                    $TargetAccountName = $Matches[1]
                }
                elseif ($line -cmatch "\s+Account\sDomain:\s+(\S.*)")
                {
                    $TargetAccountDomain = $Matches[1]
                }
            }
            elseif ($TargetServer -eq $true)
            {
                if ($line -cmatch "\s+Target\sServer\sName:\s+(\S.*)")
                {
                    $TargetServer = $Matches[1]
                }
            }
        }

        #Filter out logins that don't matter
        if (-not ($TargetAccountName -cmatch "^DWM-.*" -and $TargetAccountDomain -cmatch "^Window\sManager$"))
        {
            $Key = $SourceAccountName + $SourceAccountDomain + $TargetAccountName + $TargetAccountDomain + $TargetServer
            if (-not $ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    LogType = 4648
                    LogSource = "Security"
                    SourceAccountName = $SourceAccountName
                    SourceDomainName = $SourceAccountDomain
                    TargetAccountName = $TargetAccountName
                    TargetDomainName = $TargetAccountDomain
                    TargetServer = $TargetServer
                    Count = 1
                    Times = @($ExplicitLogon.TimeGenerated)
                }

                $ResultObj = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $ResultObj)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$ExplicitLogon.TimeGenerated
            }
        }
    }

    return $ReturnInfo
}

function Find-4624Logons
{
<#
.SYNOPSIS

Find all unique 4624 Logon events to the server. This will tell you who is logging in and how. You can use this to figure out what accounts do
network logons in to the server, what accounts RDP in, what accounts log in locally, etc...

Function: Find-4624Logons
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Find all unique 4624 Logon events to the server. This will tell you who is logging in and how. You can use this to figure out what accounts do
network logons in to the server, what accounts RDP in, what accounts log in locally, etc...

.EXAMPLE

Find-4624Logons
Find unique 4624 logon events.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    Param (
        $SecurityLog
    )

    $Logons = $SecurityLog | Where {$_.InstanceID -eq 4624}
    $ReturnInfo = @{}

    foreach ($Logon in $Logons)
    {
        $SubjectSection = $false
        $NewLogonSection = $false
        $NetworkInformationSection = $false
        $AccountName = ""
        $AccountDomain = ""
        $LogonType = ""
        $NewLogonAccountName = ""
        $NewLogonAccountDomain = ""
        $WorkstationName = ""
        $SourceNetworkAddress = ""
        $SourcePort = ""

        foreach ($line in $Logon.Message -Split "\r\n")
        {
            if ($line -cmatch "^Subject:$")
            {
                $SubjectSection = $true
            }
            elseif ($line -cmatch "^Logon\sType:\s+(\S.*)")
            {
                $LogonType = $Matches[1]
            }
            elseif ($line -cmatch "^New\sLogon:$")
            {
                $SubjectSection = $false
                $NewLogonSection = $true
            }
            elseif ($line -cmatch "^Network\sInformation:$")
            {
                $NewLogonSection = $false
                $NetworkInformationSection = $true
            }
            elseif ($SubjectSection)
            {
                if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
                {
                    $AccountName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
                {
                    $AccountDomain = $Matches[1]
                }
            }
            elseif ($NewLogonSection)
            {
                if ($line -cmatch "^\s+Account\sName:\s+(\S.*)")
                {
                    $NewLogonAccountName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Account\sDomain:\s+(\S.*)")
                {
                    $NewLogonAccountDomain = $Matches[1]
                }
            }
            elseif ($NetworkInformationSection)
            {
                if ($line -cmatch "^\s+Workstation\sName:\s+(\S.*)")
                {
                    $WorkstationName = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Source\sNetwork\sAddress:\s+(\S.*)")
                {
                    $SourceNetworkAddress = $Matches[1]
                }
                elseif ($line -cmatch "^\s+Source\sPort:\s+(\S.*)")
                {
                    $SourcePort = $Matches[1]
                }
            }
        }

        #Filter out logins that don't matter
        if (-not ($NewLogonAccountDomain -cmatch "NT\sAUTHORITY" -or $NewLogonAccountDomain -cmatch "Window\sManager"))
        {
            $Key = $AccountName + $AccountDomain + $NewLogonAccountName + $NewLogonAccountDomain + $LogonType + $WorkstationName + $SourceNetworkAddress + $SourcePort
            if (-not $ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    LogType = 4624
                    LogSource = "Security"
                    SourceAccountName = $AccountName
                    SourceDomainName = $AccountDomain
                    NewLogonAccountName = $NewLogonAccountName
                    NewLogonAccountDomain = $NewLogonAccountDomain
                    LogonType = $LogonType
                    WorkstationName = $WorkstationName
                    SourceNetworkAddress = $SourceNetworkAddress
                    SourcePort = $SourcePort
                    Count = 1
                    Times = @($Logon.TimeGenerated)
                }

                $ResultObj = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $ResultObj)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$Logon.TimeGenerated
            }
        }
    }

    return $ReturnInfo
}


function Find-AppLockerLogs
{
<#
.SYNOPSIS

Look through the AppLocker logs to find processes that get run on the server. You can then backdoor these exe's (or figure out what they normally run).

Function: Find-AppLockerLogs
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Look through the AppLocker logs to find processes that get run on the server. You can then backdoor these exe's (or figure out what they normally run).

.EXAMPLE

Find-AppLockerLogs
Find process creations from AppLocker logs.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    $ReturnInfo = @{}

    $AppLockerLogs = Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -ErrorAction SilentlyContinue | Where {$_.Id -eq 8002}

    foreach ($Log in $AppLockerLogs)
    {
        $SID = New-Object System.Security.Principal.SecurityIdentifier($Log.Properties[7].Value)
        $UserName = $SID.Translate( [System.Security.Principal.NTAccount])

        $ExeName = $Log.Properties[10].Value

        $Key = $UserName.ToString() + "::::" + $ExeName

        if (!$ReturnInfo.ContainsKey($Key))
        {
            $Properties = @{
                Exe = $ExeName
                User = $UserName.Value
                Count = 1
                Times = @($Log.TimeCreated)
            }

            $Item = New-Object PSObject -Property $Properties
            $ReturnInfo.Add($Key, $Item)
        }
        else
        {
            $ReturnInfo[$Key].Count++
            $ReturnInfo[$Key].Times += ,$Log.TimeCreated
        }
    }

    return $ReturnInfo
}


Function Find-PSScriptsInPSAppLog
{
<#
.SYNOPSIS

Go through the PowerShell operational log to find scripts that run (by looking for ExecutionPipeline logs eventID 4100 in PowerShell app log).
You can then backdoor these scripts or do other malicious things.

Function: Find-AppLockerLogs
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Go through the PowerShell operational log to find scripts that run (by looking for ExecutionPipeline logs eventID 4100 in PowerShell app log).
You can then backdoor these scripts or do other malicious things.

.EXAMPLE

Find-PSScriptsInPSAppLog
Find unique PowerShell scripts being executed from the PowerShell operational log.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    $ReturnInfo = @{}
    $Logs = Get-WinEvent -LogName "Microsoft-Windows-PowerShell/Operational" -ErrorAction SilentlyContinue | Where {$_.Id -eq 4100}

    foreach ($Log in $Logs)
    {
        $ContainsScriptName = $false
        $LogDetails = $Log.Message -split "`r`n"

        $FoundScriptName = $false
        foreach($Line in $LogDetails)
        {
            if ($Line -imatch "^\s*Script\sName\s=\s(.+)")
            {
                $ScriptName = $Matches[1]
                $FoundScriptName = $true
            }
            elseif ($Line -imatch "^\s*User\s=\s(.*)")
            {
                $User = $Matches[1]
            }
        }

        if ($FoundScriptName)
        {
            $Key = $ScriptName + "::::" + $User

            if (!$ReturnInfo.ContainsKey($Key))
            {
                $Properties = @{
                    ScriptName = $ScriptName
                    UserName = $User
                    Count = 1
                    Times = @($Log.TimeCreated)
                }

                $Item = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $Item)
            }
            else
            {
                $ReturnInfo[$Key].Count++
                $ReturnInfo[$Key].Times += ,$Log.TimeCreated
            }
        }
    }

    return $ReturnInfo
}


Function Find-RDPClientConnections
{
<#
.SYNOPSIS

Search the registry to find saved RDP client connections. This shows you what connections an RDP client has remembered, indicating what servers the user 
usually RDP's to.

Function: Find-RDPClientConnections
Author: Joe Bialek, Twitter: @JosephBialek
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Search the registry to find saved RDP client connections. This shows you what connections an RDP client has remembered, indicating what servers the user 
usually RDP's to.

.EXAMPLE

Find-RDPClientConnections
Find unique saved RDP client connections.

.NOTES

.LINK

Blog: http://clymb3r.wordpress.com/
Github repo: https://github.com/clymb3r/PowerShell
#>
    $ReturnInfo = @{}

    New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS | Out-Null

    #Attempt to enumerate the servers for all users
    $Users = Get-ChildItem -Path "HKU:\"
    foreach ($UserSid in $Users.PSChildName)
    {
        $Servers = Get-ChildItem "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers" -ErrorAction SilentlyContinue

        foreach ($Server in $Servers)
        {
            $Server = $Server.PSChildName
            $UsernameHint = (Get-ItemProperty -Path "HKU:\$($UserSid)\Software\Microsoft\Terminal Server Client\Servers\$($Server)").UsernameHint
                
            $Key = $UserSid + "::::" + $Server + "::::" + $UsernameHint

            if (!$ReturnInfo.ContainsKey($Key))
            {
                $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
                $User = ($SIDObj.Translate([System.Security.Principal.NTAccount])).Value

                $Properties = @{
                    CurrentUser = $User
                    Server = $Server
                    UsernameHint = $UsernameHint
                }

                $Item = New-Object PSObject -Property $Properties
                $ReturnInfo.Add($Key, $Item)
            }
        }
    }

    return $ReturnInfo
}
