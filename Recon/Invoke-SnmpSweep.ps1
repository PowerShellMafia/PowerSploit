
<#

.SYNOPSIS

SNMP Recon Module

Author: Dave (https://zerodaveexploit.wordpress.com/)
License: BSD 3-Clause
Required Depencencies: Snmputil.exe should be present on the system (http://technet.microsoft.com/en-us/library/cc722584.aspx), but if it's not, this script can optionally write it to disk temporarily and clean up provided you add in your own base64 encoded snmputil.exe (I can't redistribute it).
Version 0.1

.DESCRIPTION

It's purely reconnaissance and queries the target hosts over SNMP to get info like:

*Local user accounts (Are there local accounts that shouldn't be here?)
*Installed software (Is vulnerable third party software installed?)
*Running processes (Is this box running SQL? SCOM? etc.)
*Established/Listening TCP and UDP connections (so you can port scan without a port scan)
*Remote IPs and ports for the connections (see relationships between servers, e.g., "Who does the web server talk to?  On what port?  Where is XYZ sending its data?"
*NIC info (Which servers are dual (or more) homed?  What are the IPs?)

Some things that makes this tactic nice is that you don't need a valid domain account to get any of this info, just the SNMP community string. This is good info to enumerate prior to launching any attacks as it transposes the normal noisiness of recon into something that is hopefully less noticeable in the event logs.

.EXAMPLE

C:\PS> . .\Invoke-SnmpSweep.ps1
C:\PS> Invoke-SnmpSweep -hosts @("host1", "host2", "hostN") -community "SecretButSharedEverywhere" -reports "all" -writeTmp "true"

    -hosts - An array of systems to run against.  Easier way to do this might be to read from a file and use that.  
            E.g., $hosts = Get-Content servers.txt; Invoke-SnmpSweep -hosts $hosts

    -community - The SNMP community string.  Obtain it either by brute forcing, or grabbing it from a captured system.
            Control Panel > Administrative Tools > Services > SNMP Service > Traps

    -reports - The category of information you want to query
        Possible -report options are: 'process', 'tcp', 'udp', 'users', 'ips', 'sw', and 'all'
	    Default is "all"

    -writeTmp - Whether its okay to write a temporary snmputil.exe in case it isn't already present on the system.
        Writes to C:\windows\temp\snmputil.exe
	    Default is "false"

        *Note:  I probably can't redistribute Microsoft's snmputil.exe, so you'll need to obtain it, then use the helper code in this script to convert it to a base64 string


#>


# Check if the SNMP community is valid against this host to prevent further queries from being run against it if not.
Function CheckError($cmd, $target, $community)
{
	$out = iex "$cmd walk $target $community .1.3.6.1.2.1.1.5"

	Try
	{
	If ($out.Contains("error"))
	{
		#Write-Output "[!] There was an error running against $target"
		Write-Output "[!] Error: $out"
		If ($out.CompareTo("error on SnmpMgrOpen 0") -eq 0)
		{ 
			Write-Output "[!] Could not reach $target, probably a network / ACL issue" 
		}
		ElseIf ($out.CompareTo("error on SnmpMgrRequest 40") -eq 0)
		{
			Write-Output "[!] Bad community string?"
		}
		
		return ""
	}
	Else
	{
		return $False
	}
	}
	Catch
	{
		return $False
	}
}


Function CheckSnmpUtil($cmd)
{
	try
	{
		$tmp = iex $cmd
	}
	catch
	{
		#Write-Output "[!] This system doesn't have $cmd installed."
		return $false
	}

    return $true
}

# Only used if Microsoft's snmputil.exe isn't found and user has specifically allowed writing of tmp files with -writeTmp option to the script.
# If written, it'll be cleaned up at the end
# Note, you need to fill in the file's base64 value here because I'm not permitted to just redistribute it.
Function CreateTempSnmpUtil($snmpTmpPath = "C:\windows\temp\snmputil.exe")
{
    $snmpUtilb64 = ""

    if ([string]::IsNullOrEmpty($snmpUtilb64))
    {
        return $false
    }
    else 
    {
        $ByteArray = [System.Convert]::FromBase64String($snmpUtilb64);
        [System.IO.File]::WriteAllBytes($snmpTmpPath, $ByteArray);
        return $snmpTmpPath
    }
}

Function GetKeyFromVal($hash, $val) 
{
	$hash.getenumerator() | % { if ($_.value -eq $val){ return $_.key }}
}

# Returns an array of values corresponding to the queried OID.
# E.g., querying for system users will return ["Account1"],["Account2]
Function SnmpGet ($cmd, $target, $community, $oid)
{
	$out = iex "$cmd walk $target $community $oid"
	$linerex = "Variable\s+=\s+(?:[\w\d\.]+)\s"
	$results = $out -split $linerex
	$return = @()
	
	foreach ($line in $results)
	{
		If ($line -match "Value\s+=\s")
		{
			$line = $line -replace "Value\s+=\s+(String|TimeTicks|Integer32|IpAddress|ObjectID)\s{1}",""
			$return += $line
		}
	}
	return $return
}

# Iterate over targets array and print TSV to screen.  User can decide what to do with the output.
# $report contains what you want to query.   Default is 'all'
Function RunSnmpSweep ($servers, $community, $report="all", $snmp_cmd)
{
    #$all_oids = @{ "System Name" = ".1.3.6.1.2.1.1.5"; "Domain" = ".1.3.6.1.4.1.77.1.4"; "Host Uptime" = ".1.3.6.1.2.1.25.1.1"; "System sysuptime" = ".1.3.6.1.2.1.1.3"; "Drives" = ".1.3.6.1.2.1.25.2.3.1.3"; "Local users" = ".1.3.6.1.4.1.77.1.2.25"; "Running Processes" = ".1.3.6.1.2.1.25.4.2.1.2" ;  "Process Status" = ".1.3.6.1.2.1.25.4.2.1.7" ;  "Commandline Params" = ".1.3.6.1.2.1.25.4.2.1.5" ;  "Installed software" = ".1.3.6.1.2.1.25.6.3.1.2" ;  "SW Installed Date" = ".1.3.6.1.2.1.25.6.3.1.5"; "Route Destinations" = ".1.3.6.1.2.1.4.21.1" ;  "IP Addresses" = ".1.3.6.1.2.1.4.20.1.1" ;  "TCP Table Conn Status" = ".1.3.6.1.2.1.6.13.1.1" ;  "TCP Table Local IP" = ".1.3.6.1.2.1.6.13.1.2" ;  "TCP Table Local Port" = ".1.3.6.1.2.1.6.13.1.3" ; "TCP Table Remote IP" = ".1.3.6.1.2.1.6.13.1.4" ;  "TCP Table Remote Port" = ".1.3.6.1.2.1.6.13.1.5" ;  "UDP Table Remote IP" = ".1.3.6.1.2.1.7.5.1.1" ;  "UDP Table Local Port" = ".1.3.6.1.2.1.7.5.1.2" }

    # Report 1:  Process info
    if ($report -eq "all" -or $report -eq "process")
    {
        # TSV Headers
        Write-Output "Name`tDomain`tProcName`tStatus`tArgs"
        foreach ($server in $servers)
        {
            $Str_server_name = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.1.5"
            $Str_server_domain = SnmpGet $snmp_cmd $server $community ".1.3.6.1.4.1.77.1.4"
            $Arr_running_processes = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.25.4.2.1.2"
            $Arr_process_status = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.25.4.2.1.7"
            $Arr_process_args = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.25.4.2.1.5"

            # Write out report, fix status code too
            for ($i = 0; $i -lt $Arr_process_status.length; $i++)
            {
                $Arr_process_status[$i] = $Arr_process_status[$i] -replace "1","Running"
                $Arr_process_status[$i] = $Arr_process_status[$i] -replace "2","Runnable"
                $Arr_process_status[$i] = $Arr_process_status[$i] -replace "3","Not Runnable"
                $Arr_process_status[$i] = $Arr_process_status[$i] -replace "4","Invalid"

                Write-Output "$Str_server_name`t$Str_server_domain`t$($Arr_running_processes[$i])`t$($Arr_process_status[$i])`t$($Arr_process_args[$i])"

            }

        }

        Write-Output "`n`n"
    }

    # Report 2: TCP Connections
    if ($report -eq "all"  -or $report -eq "tcp")
    {
        Write-Output "Name`tDomain`tLocalIP`tLocalPort`tRemoteIP`tRemotePort`tConnStatus"

        foreach ($server in $servers)
        {
            $Str_server_name = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.1.5"
            $Str_server_domain = SnmpGet $snmp_cmd $server $community ".1.3.6.1.4.1.77.1.4"
            $tcp_local_ip = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.6.13.1.2"
            $tcp_local_port = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.6.13.1.3"
            $tcp_remote_ip = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.6.13.1.4"
            $tcp_remote_port = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.6.13.1.5"
            $tcp_status = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.6.13.1.1"

            for ($i = 0; $i -lt $tcp_status.length; $i++)
            {
                # Make human readable
                $tcp_status[$i] = $tcp_status[$i] -replace "1","Closed"
                $tcp_status[$i] = $tcp_status[$i] -replace "2","Listen"
                $tcp_status[$i] = $tcp_status[$i] -replace "3","SynSent"
                $tcp_status[$i] = $tcp_status[$i] -replace "4","SynReceived"
                $tcp_status[$i] = $tcp_status[$i] -replace "5","Established"
                $tcp_status[$i] = $tcp_status[$i] -replace "6","FinWait1"
                $tcp_status[$i] = $tcp_status[$i] -replace "7","FinWait2"
                $tcp_status[$i] = $tcp_status[$i] -replace "8","CloseWait"
                $tcp_status[$i] = $tcp_status[$i] -replace "9","LastACK"
                $tcp_status[$i] = $tcp_status[$i] -replace "10","Closing"
                $tcp_status[$i] = $tcp_status[$i] -replace "11","TimeWait"
                $tcp_status[$i] = $tcp_status[$i] -replace "12","DeleteTCB"

                Write-Output "$Str_server_name`t$Str_server_domain`t$($tcp_local_ip[$i])`t$($tcp_local_port[$i])`t$($tcp_remote_ip[$i])`t$($tcp_remote_port[$i])`t$( $tcp_status[$i] )"

            }
        }

        Write-Output "`n`n"
    }

    # Report 3: UDP Connections
    if ($report -eq "all"  -or $report -eq "udp")
    {
        Write-Output "Name`tDomain`tRemoteIP`tLocalPort"

        foreach ($server in $servers)
        {
            $Str_server_name = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.1.5"
            $Str_server_domain = SnmpGet $snmp_cmd $server $community ".1.3.6.1.4.1.77.1.4"
            $udp_remote_ip = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.7.5.1.1"
            $udp_local_port = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.7.5.1.2"

            for ($i = 0; $i -lt $udp_remote_ip.length; $i++)
            {
                Write-Output "$Str_server_name`t$Str_server_domain`t$($udp_remote_ip[$i])`t$($udp_local_port[$i])"
            }
        }
        Write-Output "`n`n"
    }

    # Report 4: Local Users
    if ($report -eq "all"  -or $report -eq "users")
    {
        Write-Output "Name`tDomain`tLocalUserAccounts"

        foreach ($server in $servers)
        {
            $Str_server_name = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.1.5"
            $Str_server_domain = SnmpGet $snmp_cmd $server $community ".1.3.6.1.4.1.77.1.4"
            $local_users = SnmpGet $snmp_cmd $server $community ".1.3.6.1.4.1.77.1.2.25"

            for ($i = 0; $i -lt $local_users.length; $i++)
            {
                Write-Output "$Str_server_name`t$Str_server_domain`t$($local_users[$i])"
            }
        }
        Write-Output "`n`n"
    }

    # Report 5: Multihomed Systems
    if ($report -eq "all"  -or $report -eq "ips")
    {
        Write-Output "Name`tDomain`tNetworkInterfaces"

        foreach ($server in $servers)
        {
            $Str_server_name = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.1.5"
            $Str_server_domain = SnmpGet $snmp_cmd $server $community ".1.3.6.1.4.1.77.1.4"
            $ip_addresses = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.4.20.1.1"

            for ($i = 0; $i -lt $ip_addresses.length; $i++)
            {
                Write-Output "$Str_server_name`t$Str_server_domain`t$($ip_addresses[$i])"
            }
        }
        Write-Output "`n`n"
    }


    # Report 6: Installed Software
    # Installed software  .1.3.6.1.2.1.25.6.3.1.2
    # Installed Date  .1.3.6.1.2.1.25.6.3.1.5
    # Excluding date for now, will dev a way to make human readable if this is important
    if ($report -eq "all"  -or $report -eq "sw")
    {
        Write-Output "Name`tDomain`tSoftware"

        foreach ($server in $servers)
        {
            $Str_server_name = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.1.5"
            $Str_server_domain = SnmpGet $snmp_cmd $server $community ".1.3.6.1.4.1.77.1.4"
            $installed_software = SnmpGet $snmp_cmd $server $community ".1.3.6.1.2.1.25.6.3.1.2"
            $install_date = SnmpGet $snmp_cmd $server $community " .1.3.6.1.2.1.25.6.3.1.5"

            for ($i = 0; $i -lt $installed_software.length; $i++)
            {
                Write-Output "$Str_server_name`t$Str_server_domain`t$($installed_software[$i])"
            }
        }
        Write-Output "`n`n"
    }

}



####### Main Function #######
Function Invoke-SnmpSweep
{

[cmdletbinding()] Param (
	[array]$hosts,
	[string]$community,
	[string]$reports = "all",
	[string]$writeTmp = "false"
	)

    $snmp_cmd = "snmputil"
    $snmpTmpPath = "C:\windows\temp\snmputil.exe"
    $cleanup = $false

    if ( (CheckSnmpUtil $snmp_cmd) -eq $false )
    {
        if ($writeTmp -match "^true")
        {
            $snmp_cmd = CreateTempSnmpUtil
            if ($snmp_cmd -eq $false) # false returned if the user hasn't specified b64 data for the binary
            { 
                Write-Output "`n[!] Error: snmputil.exe was not found on this system, and you haven't added it to this script"
                Write-Output "`n`tObtain it from the Windows NT Resource Kit (I probaby can't redistribute it), or from one of your servers"
                Write-Output "`tThen convert it to a base64 string and paste it into the value of the `$snmpUtilb64 variable in this script"
                Write-Output "`tReference: http://support.microsoft.com/kb/232663"
                Write-Output "`tExample code:"
                Write-Output "Function ConvertToB64(`$FilePath)`n{`n`t`$ByteArray = [System.IO.File]::ReadAllBytes(`$FilePath);`n`t`$Base64String = [System.Convert]::ToBase64String(`$ByteArray);`n`treturn `$Base64String`n}"
                return "" 
            }

            Write-Output "[*] Created temp snmputil.exe in $snmpTmpPath"
            $cleanup = $true
        }
		else
        {
            Write-Output "`n[!] SnmpUtil.exe was not found on this system and 'writeTmp' is not set to 'true' so we aren't writing it"
            Write-Output "[!] If you're okay with writing a temporary exe to the system rerun with something like: "
            Write-Output "[!] Invoke-Snmpsweep -hosts localhost -community secretString -reports all -writeTmp true" 
            Write-Output "Exiting"
            return ""
        }
    }

    $valid_hosts = @()
    
    foreach ($h in $hosts)
	{
	
        # Preprocessing

	    # Check for errors (invalid community, ACLs, etc.)
	    If($e = CheckError $snmp_cmd $h $community)
	    {
            Write-Output "[*] This community string seems to be invalid for: $h"
            Write-Output $e
		    continue
	    }
        else { $valid_hosts += $h }
	
    } # end foreach

    if ($valid_hosts.Length -gt 0) 
    {
	    RunSnmpSweep $valid_hosts $community $reports $snmp_cmd
    }
    else
    {
        Write-Output "[*] There were no hosts with known SNMP communities"
    }
   
   if ($cleanup -eq $true)
    {
        Write-Output "[*] Removing snmputil from $snmpTmpPath"
        Remove-Item $snmpTmpPath
    }

    Write-Output "[*] Done!"
} 

