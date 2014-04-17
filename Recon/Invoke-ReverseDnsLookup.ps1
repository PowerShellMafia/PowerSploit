function Invoke-ReverseDnsLookup
{
<#
.SYNOPSIS

Perform a reverse DNS lookup scan on a range of IP addresses.

PowerSploit Function: Invoke-ReverseDnsLookup
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Invoke-ReverseDnsLookup scans an IP address range for DNS PTR records. This script is useful for performing DNS reconnaisance prior to conducting an authorized penetration test.
 
.PARAMETER IPRange

Specifies the IP address range. The range provided can be in the form of a single IP address, a low-high range, or a CIDR range. Comma-delimited ranges may can be provided.
 
.EXAMPLE

C:\PS> Invoke-ReverseDnsLookup 74.125.228.0/29

IP              HostName
--              --------
74.125.228.1    iad23s05-in-f1.1e100.net
74.125.228.2    iad23s05-in-f2.1e100.net
74.125.228.3    iad23s05-in-f3.1e100.net
74.125.228.4    iad23s05-in-f4.1e100.net
74.125.228.5    iad23s05-in-f5.1e100.net
74.125.228.6    iad23s05-in-f6.1e100.net
 
Description
-----------
Returns the hostnames of the IP addresses specified by the CIDR range.
 
.EXAMPLE

C:\PS> Invoke-ReverseDnsLookup '74.125.228.1,74.125.228.4-74.125.228.6'
 
IP              HostName
--              --------
74.125.228.1    iad23s05-in-f1.1e100.net
74.125.228.4    iad23s05-in-f4.1e100.net
74.125.228.5    iad23s05-in-f5.1e100.net
74.125.228.6    iad23s05-in-f6.1e100.net
 
Description
-----------
Returns the hostnames of the IP addresses specified by the IP range specified.

.EXAMPLE

PS C:\> Write-Output "74.125.228.1,74.125.228.0/29" | Invoke-ReverseDnsLookup

IP                                                          HostName
--                                                          --------
74.125.228.1                                                iad23s05-in-f1.1e100.net
74.125.228.1                                                iad23s05-in-f1.1e100.net
74.125.228.2                                                iad23s05-in-f2.1e100.net
74.125.228.3                                                iad23s05-in-f3.1e100.net
74.125.228.4                                                iad23s05-in-f4.1e100.net
74.125.228.5                                                iad23s05-in-f5.1e100.net
74.125.228.6                                                iad23s05-in-f6.1e100.net

Description
-----------
Returns the hostnames of the IP addresses piped from another source.

  
.LINK

http://www.exploit-monday.com
https://github.com/mattifestation/PowerSploit
#>

    Param (
        [Parameter(Position = 0, Mandatory = $True,ValueFromPipeline=$True)]
        [String]
        $IpRange
    )

    BEGIN {
    
        function Parse-IPList ([String] $IpRange)
        {
        
            function IPtoInt
            {
                Param([String] $IpString)
            
                $Hexstr = ""
                $Octets = $IpString.Split(".")
                foreach ($Octet in $Octets) {
                        $Hexstr += "{0:X2}" -f [Int] $Octet
                }
                return [Convert]::ToInt64($Hexstr, 16)
            }
        
            function InttoIP
            {
                Param([Int64] $IpInt)
                $Hexstr = $IpInt.ToString("X8")
                $IpStr = ""
                for ($i=0; $i -lt 8; $i += 2) {
                        $IpStr += [Convert]::ToInt64($Hexstr.SubString($i,2), 16)
                        $IpStr += '.'
                }
                return $IpStr.TrimEnd('.')
            }
        
            $Ip = [System.Net.IPAddress]::Parse("127.0.0.1")
        
            foreach ($Str in $IpRange.Split(","))
            {
                $Item = $Str.Trim()
                $Result = ""
                $IpRegex = "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            
                # First, validate the input
                switch -regex ($Item)
                {
                    "^$IpRegex/\d{1,2}$"
                    {
                        $Result = "cidrRange"
                        break
                    }
                    "^$IpRegex-$IpRegex$"
                    {
                        $Result = "range"
                        break
                    }
                    "^$IpRegex$"
                    {
                        $Result = "single"
                        break
                    }
                    default
                    {
                        Write-Warning "Inproper input"
                        return
                    }
                }
            
                #Now, start processing the IP addresses
                switch ($Result)
                {
                    "cidrRange"
                    {
                        $CidrRange = $Item.Split("/")
                        $Network = $CidrRange[0]
                        $Mask = $CidrRange[1]
                    
                        if (!([System.Net.IPAddress]::TryParse($Network, [ref] $Ip))) { Write-Warning "Invalid IP address supplied!"; return}
                        if (($Mask -lt 0) -or ($Mask -gt 30)) { Write-Warning "Invalid network mask! Acceptable values are 0-30"; return}
                    
                        $BinaryIP = [Convert]::ToString((IPtoInt $Network),2).PadLeft(32,'0')
                        #Generate lower limit (Excluding network address)
                        $Lower = $BinaryIP.Substring(0, $Mask) + "0" * ((32-$Mask)-1) + "1"
                        #Generate upperr limit (Excluding broadcast address)
                        $Upper = $BinaryIP.Substring(0, $Mask) + "1" * ((32-$Mask)-1) + "0"
                        $LowerInt = [Convert]::ToInt64($Lower, 2)
                        $UpperInt = [Convert]::ToInt64($Upper, 2)
                        for ($i = $LowerInt; $i -le $UpperInt; $i++) { InttoIP $i }
                    }
                    "range"
                    {
                        $Range = $item.Split("-")
                    
                        if ([System.Net.IPAddress]::TryParse($Range[0],[ref]$Ip)) { $Temp1 = $Ip }
                        else { Write-Warning "Invalid IP address supplied!"; return }
                    
                        if ([System.Net.IPAddress]::TryParse($Range[1],[ref]$Ip)) { $Temp2 = $Ip }
                        else { Write-Warning "Invalid IP address supplied!"; return }
                    
                        $Left = (IPtoInt $Temp1.ToString())
                        $Right = (IPtoInt $Temp2.ToString())
                    
                        if ($Right -gt $Left) {
                            for ($i = $Left; $i -le $Right; $i++) { InttoIP $i }
                        }
                        else { Write-Warning "Invalid IP range. The right portion must be greater than the left portion."; return}
                    
                        break
                    }
                    "single"
                    {
                        if ([System.Net.IPAddress]::TryParse($Item,[ref]$Ip)) { $Ip.IPAddressToString }
                        else { Write-Warning "Invalid IP address supplied!"; return }
                        break
                    }
                    default
                    {
                        Write-Warning "An error occured."
                        return
                    }
                }
            }
        
        }
    }
    
    PROCESS {
        Parse-IPList $IpRange | ForEach-Object {
            try {
                Write-Verbose "Resolving $_"
                $Temp = [System.Net.Dns]::GetHostEntry($_)
            
                $Result = @{
                    IP = $_
                    HostName = $Temp.HostName
                }
            
                New-Object PSObject -Property $Result
            } catch [System.Net.Sockets.SocketException] {}
        }
    }
}
