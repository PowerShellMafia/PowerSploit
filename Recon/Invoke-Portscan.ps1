function Invoke-Portscan
{
<#
.SYNOPSIS

Simple portscan module

PowerSploit Function: Invoke-Portscan
Author: Rich Lundeen (http://webstersProdigy.net)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Does a simple port scan using regular sockets, based (pretty) loosely on nmap

.NOTES

version .12

.EXAMPLE

C:\PS> Invoke-Portscan -v -Hosts "webstersprodigy.net,google.com,microsoft.com" -topPorts 30

Description
-----------
Scans the top 30 ports for hosts found for webstersprodigy.net,google.com, and microsoft.com


.EXAMPLE

C:\PS> echo webstersprodigy.net | Invoke-Portscan -oG test.gnmap -f -ports "80,443,8080"

Description
-----------
Does a portscan of "webstersprodigy.net", and writes a greppable output file


.EXAMPLE

C:\PS> Invoke-Portscan -Hosts 192.168.1.1/24 -T 4 -topPorts 25 -v -oA localnet

Description
-----------
Scans the top 20 ports for hosts found in the 192.168.1.1/24 range, outputs all file formats


.LINK

http://webstersprodigy.net
#>

    [CmdletBinding()]Param (
        #Host, Ports
        [Parameter(ParameterSetName="cmdHosts", 
                   ValueFromPipeline=$True,
                   Mandatory = $True,
                   HelpMessage = "include these comma seperated hosts (supports IPv4 CIDR notation), or pipe them in"  )] 
                   [String[]] $Hosts,                     

        [Parameter(ParameterSetName="fHosts",
                   Mandatory = $True,
                   HelpMessage = "input hosts from file")]
                   [String]  $iL,

        [Parameter(Mandatory = $False,
                   HelpMessage = "exclude these comma seperated hosts")]
                   [String] $exclude,

        [Parameter(Mandatory = $False,
                   HelpMessage = "include these comma seperated ports (can also be a range like 80-90)")]
                   [String] $Ports,

        [Parameter(Mandatory = $False,
                   HelpMessage = "input ports from a file")]
                   [String] $iP,

        [Parameter(Mandatory = $False,
                   HelpMessage = "include the x top ports - only goes to 1000, default is top 50")]
                   [String] $topPorts,

        [Parameter(Mandatory = $False,
                   HelpMessage = "exclude these comma seperated ports")]
                   [String] $xPorts,

        #Host Discovery
        [Parameter(Mandatory = $False,
                   HelpMessage = "treat all hosts as online, skip host discovery")]
                   [Switch] $Pn,

        [Parameter(Mandatory = $False,
                   HelpMessage = "Ping scan only (disable port scan)")]
                   [Switch] $sn,

        [Parameter(Mandatory = $False,
                   HelpMessage = "comma separated ports for discovery. -1 is a ping")]
                   [string] $PS = "-1,445,80,443",

        #Timing and Performance
        [Parameter(Mandatory = $False,
                   HelpMessage = "number of max threads for the thread pool (per host)")]
                   [int] $Threads = 100,

        [Parameter(Mandatory = $False,
                   HelpMessage = "number of hosts to concurrently scan")]
                   [int] $nHosts = 25,

        [Parameter(Mandatory = $False,
                   HelpMessage = "timeout time on a connection in miliseconds")]
                   [int] $Timeout = 2000,

        [Parameter(Mandatory = $False,
                   HelpMessage = "wait before thread checking, in miliseconds")]
                   [int] $sleepTimer = 500,

        [Parameter(Mandatory = $False,
                    HelpMessage = "how often (in terms of hosts) to sync threads and flush output")]
                   [int] $syncFreq = 1024,

        [Parameter(Mandatory = $False,
                   HelpMessage = "[0-5] shortcut performance options. Default is 3. higher is more aggressive. Sets (nhosts, threads,timeout)
                   5: (40,1000,750) 4: (30,1000,1200) 3: (25,100,2000) 2:(20,32,2500) 1:(10,32,5000)")]
                   [int] $T,

        #Output
        [Parameter(Mandatory = $False,
                   HelpMessage = "Greppable output file")]
                   [String] $oG,

        [Parameter(Mandatory = $False,
                   HelpMessage = "output in xml")]
                   [String] $oX,

        [Parameter(Mandatory = $False,
                   HelpMessage = "output in 'readable' format")]
                   [String] $oN,

        [Parameter(Mandatory = $False,
                   HelpMessage = "output in readable and xml format in addition to greppable.")]
                   [String] $oA,

        [Parameter(Mandatory = $False,
                   HelpMessage = "gives a progress meter")]
                   [Switch] $v,

        [Parameter(Mandatory = $False,
                   HelpMessage = "supresses output")]
                   [Switch] $q,

        [Parameter(Mandatory = $False,
                   HelpMessage = "Force Overwrite if output Files exist. Otherwise it throws exception")]
                   [Switch] $F

        #TODO add script parameter
        #TODO add resume parameter
    )

    PROCESS {

        $version = .12
        $hostList = New-Object System.Collections.ArrayList
        $portList = New-Object System.Collections.ArrayList
        $hostPortList = New-Object System.Collections.ArrayList

        function Parse-Hosts
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $Hosts
            )

            [String[]] $iHosts = $Hosts.Split(",")

            foreach($iHost in $iHosts)
            {
                $iHost = $iHost.Replace(" ", "")

                if(!$iHost)
                {
                    continue
                }

                if($iHost.contains("/"))
                {
                    $netPart = $iHost.split("/")[0]
                    [uint32]$maskPart = $iHost.split("/")[1]

                    $address = [System.Net.IPAddress]::Parse($netPart)

                    if ($maskPart -ge $address.GetAddressBytes().Length * 8)
                    {
                        throw "Bad host mask"
                    }

                    $numhosts = [System.math]::Pow(2,(($address.GetAddressBytes().Length *8) - $maskPart))

                    #if address is ipv4 then parse cidr the easy way
                    #Once 3.0 support is more universal, this can be taken out and go directly to the 'else'
                    if ($address.AddressFamily -eq "InterNetwork")
                    {

                        $startaddress = $address.GetAddressBytes()
                        [array]::Reverse($startaddress)

                        $startaddress = [System.BitConverter]::ToUInt32($startaddress, 0)
                        [uint32]$startMask = ([System.math]::Pow(2, $maskPart)-1) * ([System.Math]::Pow(2,(32 - $maskPart)))
                        $startAddress = $startAddress -band $startMask

                        #in powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
                        $startAddress = [System.BitConverter]::GetBytes($startaddress)[0..3]
                        [array]::Reverse($startaddress)

                        $address = [System.Net.IPAddress] [byte[]] $startAddress

                        $hostList.Add($address.IPAddressToString)

                        for ($i=0; $i -lt $numhosts-1; $i++)
                        {

                            $nextAddress =  $address.GetAddressBytes()
                            [array]::Reverse($nextAddress)
                            $nextAddress =  [System.BitConverter]::ToUInt32($nextAddress, 0)
                            $nextAddress ++
                            $nextAddress = [System.BitConverter]::GetBytes($nextAddress)[0..3]
                            [array]::Reverse($nextAddress)

                            $address = [System.Net.IPAddress] [byte[]] $nextAddress
                            $hostList.Add($address.IPAddressToString)

                        }

                    }

                    #if ipv6 CIDR notation, then there's a ps 3.0 requirement due to biginteger
                    else
                    {

                        #Get start address
                        $startAddress = $address.GetAddressBytes()
                        $numbits = $startAddress.Length * 8
                        [array]::Reverse($startAddress)

                        $startAddress = ([System.Numerics.BigInteger] [byte[]]$startAddress)

                        $startMask = ([System.Numerics.BigInteger]::Pow(2, $maskPart)-1) * ([System.Math]::Pow(2,(128 - $maskPart)))
                        $startAddress = $startAddress -band $startMask

                        $startAddress = $startAddress.ToByteArray()
                        [array]::Reverse($startAddress)

                        #strip out leading 0 put in by BigIneger, if any
                        if ($startAddress[0] -eq 0)
                        {
                            $startAddress = $startAddress[1..$startAddress.Length]
                        }

                        $address = [System.Net.IPAddress] [byte[]] $startAddress
                        $hostList.Add($address.IPAddressToString)

                        for ($i=0; $i -lt $numhosts-1; $i++)
                        {
                            $nextAddress =  $address.GetAddressBytes()
                            [array]::Reverse($nextAddress)
                            $nextAddress =  ([System.Numerics.BigInteger] [byte[]]$nextAddress) + 1
                            $nextAddress = $nextAddress.ToByteArray()
                            [array]::Reverse($nextAddress)

                            $address = [System.Net.IPAddress] [byte[]] $nextAddress
                            $hostList.Add($address.IPAddressToString)

                        }
                    }
                }
                else
                {
                    try
                    {
                        $address = [System.Net.IPAddress]::Parse($iHost)
                        $hostList.Add($address.IPAddressToString)
                    }
                    catch
                    {
                        #we're assuming this is a host name
                        $hostList.Add($iHost)
                    }
                }
            }
        }

        function Parse-ILHosts
        {
           Param (
                [Parameter(Mandatory = $True)] [String] $HostFile
            )

            Get-Content $HostFile | ForEach-Object {
                Parse-Hosts $_
            }
        }

        function Exclude-Hosts
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $excludeHosts
            )

            [String[]] $iHosts = $excludeHosts.Split(",")

            foreach($iHost in $iHosts)
            {
                $iHost = $iHost.Replace(" ", "")
                $hostList.Remove($iHost)
            }
        }

        function Get-TopPort
        {
            Param (
                [Parameter(Mandatory = $True)] [int] $numPorts
            )

            if ($numPorts -gt 1000 -or $numPorts -lt 0)
            {
                throw "Topports out of range - only supports top 1000"
            }

            #list of top 1000 ports from nmap from Jun 2013
            [int[]] $topPortList = @(80,23,443,21,3389,110,445,139,143,53,135,3306,8080,22
                        1723,111,995,993,5900,1025,1720,548,113,81,6001,179,1026,2000,8443,
                        8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,
                        5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,
                        990,5357,49156,543,544,5101,144,7,389,8009,9999,5009,7070,5190,3000,
                        5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,
                        119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,
                        5050,19,8031,1041,255,1048,1049,1053,1054,1056,1064,3703,17,808,3689,
                        1031,1044,1071,5901,100,9102,2869,4001,5120,8010,9000,2105,636,1038,
                        2601,1,7000,1066,1069,625,311,280,254,4000,1761,5003,2002,1998,2005,
                        1032,1050,6112,1521,2161,6002,2401,902,4045,787,7937,1058,2383,1033,
                        1040,1059,50000,5555,1494,3,593,2301,3268,7938,1022,1234,1035,1036,1037,
                        1074,8002,9001,464,497,1935,2003,6666,6543,24,1352,3269,1111,407,500,
                        20,2006,1034,1218,3260,15000,4444,264,33,2004,1042,42510,999,3052,1023,
                        222,1068,888,7100,1717,992,2008,7001,2007,8082,512,1043,2009,5801,1700,
                        7019,50001,4662,2065,42,2602,3333,9535,5100,2604,4002,5002,1047,1051,1052,
                        1055,1060,1062,1311,3283,4443,5225,5226,6059,6789,8089,8651,8652,8701,9415,
                        9593,9594,9595,16992,16993,20828,23502,32769,33354,35500,52869,55555,55600,
                        64623,64680,65000,65389,1067,13782,366,5902,9050,85,1002,5500,1863,1864,
                        5431,8085,10243,45100,49999,51103,49,90,6667,1503,6881,27000,340,1500,8021,
                        2222,5566,8088,8899,9071,5102,6005,9101,163,5679,146,648,1666,83,3476,5004,
                        5214,8001,8083,8084,9207,14238,30,912,12345,2030,2605,6,541,4,1248,3005,8007,
                        306,880,2500,1086,1088,2525,4242,8291,9009,52822,900,6101,2809,7200,211,800,
                        987,1083,12000,705,711,20005,6969,13783,1045,1046,1061,1063,1070,1072,1073,
                        1075,1077,1078,1079,1081,1082,1085,1093,1094,1096,1098,1099,1100,1104,1106,
                        1107,1108,1148,1169,1272,1310,1687,1718,1783,1840,2100,2119,2135,2144,2160,
                        2190,2260,2381,2399,2492,2607,2718,2811,2875,3017,3031,3071,3211,3300,3301,
                        3323,3325,3351,3404,3551,3580,3659,3766,3784,3801,3827,3998,4003,4126,4129,
                        4449,5222,5269,5633,5718,5810,5825,5877,5910,5911,5925,5959,5960,5961,5962,
                        5987,5988,5989,6123,6129,6156,6389,6580,6901,7106,7625,7777,7778,7911,8086,
                        8181,8222,8333,8400,8402,8600,8649,8873,8994,9002,9011,9080,9220,9290,9485,
                        9500,9502,9503,9618,9900,9968,10002,10012,10024,10025,10566,10616,10617,10621,
                        10626,10628,10629,11110,13456,14442,15002,15003,15660,16001,16016,16018,17988,
                        19101,19801,19842,20000,20031,20221,20222,21571,22939,24800,25734,27715,28201,
                        30000,30718,31038,32781,32782,33899,34571,34572,34573,40193,48080,49158,49159,
                        49160,50003,50006,50800,57294,58080,60020,63331,65129,691,212,1001,1999,2020,
                        2998,6003,7002,50002,32,2033,3372,99,425,749,5903,43,458,5405,6106,6502,7007,
                        13722,1087,1089,1124,1152,1183,1186,1247,1296,1334,1580,1782,2126,2179,2191,2251,
                        2522,3011,3030,3077,3261,3493,3546,3737,3828,3871,3880,3918,3995,4006,4111,4446,
                        5054,5200,5280,5298,5822,5859,5904,5915,5922,5963,7103,7402,7435,7443,7512,8011,
                        8090,8100,8180,8254,8500,8654,9091,9110,9666,9877,9943,9944,9998,10004,10778,15742,
                        16012,18988,19283,19315,19780,24444,27352,27353,27355,32784,49163,49165,49175,
                        50389,50636,51493,55055,56738,61532,61900,62078,1021,9040,666,700,84,545,1112,
                        1524,2040,4321,5802,38292,49400,1084,1600,2048,2111,3006,6547,6699,9111,16080,
                        555,667,720,801,1443,1533,2106,5560,6007,1090,1091,1114,1117,1119,1122,1131,1138,
                        1151,1175,1199,1201,1271,1862,2323,2393,2394,2608,2725,2909,3003,3168,3221,3322,
                        3324,3390,3517,3527,3800,3809,3814,3826,3869,3878,3889,3905,3914,3920,3945,3971,
                        4004,4005,4279,4445,4550,4567,4848,4900,5033,5080,5087,5221,5440,5544,5678,5730,
                        5811,5815,5850,5862,5906,5907,5950,5952,6025,6510,6565,6567,6689,6692,6779,6792,
                        6839,7025,7496,7676,7800,7920,7921,7999,8022,8042,8045,8093,8099,8200,8290,8292,
                        8300,8383,9003,9081,9099,9200,9418,9575,9878,9898,9917,10003,10180,10215,11111,
                        12174,12265,14441,15004,16000,16113,17877,18040,18101,19350,25735,26214,27356,
                        30951,32783,32785,40911,41511,44176,44501,49161,49167,49176,50300,50500,52673,
                        52848,54045,54328,55056,56737,57797,60443,70,417,714,722,777,981,1009,2022,4224,
                        4998,6346,301,524,668,765,2041,5999,10082,259,1007,1417,1434,1984,2038,2068,4343,
                        6009,7004,44443,109,687,726,911,1461,2035,4125,6006,7201,9103,125,481,683,903,
                        1011,1455,2013,2043,2047,6668,6669,256,406,843,2042,2045,5998,9929,31337,44442,
                        1092,1095,1102,1105,1113,1121,1123,1126,1130,1132,1137,1141,1145,1147,1149,1154,
                        1164,1165,1166,1174,1185,1187,1192,1198,1213,1216,1217,1233,1236,1244,1259,1277,
                        1287,1300,1301,1309,1322,1328,1556,1641,1688,1719,1721,1805,1812,1839,1875,1914,
                        1971,1972,1974,2099,2170,2196,2200,2288,2366,2382,2557,2800,2910,2920,2968,3007,
                        3013,3050,3119,3304,3307,3376,3400,3410,3514,3684,3697,3700,3824,3846,3848,3859,
                        3863,3870,3872,3888,3907,3916,3931,3941,3957,3963,3968,3969,3972,3990,3993,3994,
                        4009,4040,4080,4096,4143,4147,4200,4252,4430,4555,4600,4658,4875,4949,5040,5063,
                        5074,5151,5212,5223,5242,5279,5339,5353,5501,5807,5812,5818,5823,5868,5869,5899,
                        5905,5909,5914,5918,5938,5940,5968,5981,6051,6060,6068,6203,6247,6500,6504,6520,
                        6550,6600)
            $numPorts--
            $portList.AddRange($topPortList[0..$numPorts])
        }

        function Parse-Ports
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $Ports,
                [Parameter(Mandatory = $True)] $pList
            )

            foreach ($pRange in $Ports.Split(","))
            {

                #-1 is a special case for ping
                if ($pRange -eq "-1")
                {
                    $pList.Add([int]$pRange)
                }
                elseif ($pRange.Contains("-"))
                {
                    [int[]] $range = $pRange.Split("-").Trim()
                    if ($range.Count -ne 2 -or $pRange.Split("-")[0] -eq "" -or $pRange.split("-")[1] -eq "")
                    {
                        throw "Invalid port range"
                    }

                    $pList.AddRange($range[0]..$range[1])
                }
                else
                {
                    $pList.Add([int]$pRange)
                }


            }
            foreach ($p in $pList)
            {
                if ($p -lt -1 -or $p -gt 65535)
                {
                    throw "Port $p out of range"
                }
            }

         }

        function Parse-IpPorts
        {
           Param (
                [Parameter(Mandatory = $True)] [String] $PortFile
            )

            Get-Content $PortFile | ForEach-Object {
                Parse-Ports -Ports $_ -pList $portList
            }
        }

        function Remove-Ports
        {
            Param (
                [Parameter(Mandatory = $True)] [String] $xPorts
            )

            [int[]] $xPorts = $xPorts.Split(",")

            foreach ($x in $xPorts)
            {
                $portList.Remove($x)
            }
        }

        function Write-PortscanOut
        {
            Param (
                [Parameter(Mandatory = $True, ParameterSetName="Comment")] [string] $comment,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] [string] $outhost,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] [bool] $isUp,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $openPorts,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $closedPorts,
                [Parameter(Mandatory = $True, ParameterSetName="HostOut")] $filteredPorts,
                [Parameter()] [bool] $quiet,
                [Parameter()] [bool] $Pn,
                [Parameter()] [System.IO.StreamWriter] $grepStream,
                [Parameter()] [System.Xml.XmlWriter] $xmlStream,
                [Parameter()] [System.IO.StreamWriter] $readableStream

            )
            switch ($PSCmdlet.ParameterSetName)
            {
                "Comment"
                {
                    if (!$quiet) {
                        Write-Output $comment
                    }
                    if ($grepStream) {
                        $grepStream.WriteLine("# " + $comment)
                    }
                    if ($xmlStream) {
                        $xmlStream.WriteComment($comment)
                    }
                    if ($readableStream) {
                        $readableStream.WriteLine($comment)
                    }
                }
                "HostOut"
                {
                    $oPort = [string]::join(",", $openPorts.ToArray())
                    $cPort = [string]::join(",", $closedPorts.ToArray())
                    $fPort = [string]::join(",", $filteredPorts.ToArray())

                    if (!$quiet) {
                        if ($isUp -and !$Pn) {
                            Write-Output ("Host: {0,-25} Status: Up" -f $outhost)
                        }
                        if ($isUp -or $Pn) {
                            if ($oPort -ne "") {
                                Write-Output ("Host: {0,-25} Open Ports: {1,0}" -f $outhost, $oPort)
                            }
                            if ($cPort -ne "") {
                                Write-Output ("Host: {0,-25} Closed Ports: {1,0}" -f $outhost, $cPort)
                            }
                            if ($fPort -ne "") {
                                Write-Output ("Host: {0,-25} Filtered Ports: {1,0}" -f $outhost, $fPort)
                            }
                        }
                        elseif (!$Pn) {
                            Write-Output ("Host: {0,-25} Status: Down" -f $outhost)
                        }

                    }
                    if ($grepStream) {
                       #for grepstream use tabs - can be ugly, but easier for regex
                       if ($isUp -and !$Pn) {
                            $grepStream.writeline("Host: $outhost`tStatus: Up")
                        }
                        if ($isUp -or $Pn) {
                            if ($oPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tOpen Ports: $oPort")
                            }
                            if ($cPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tClosed Ports: $cPort")
                            }
                            if ($fPort -ne "") {
                                $grepStream.writeline("Host: $outhost`tFiltered Ports: $fPort")
                            }
                        }
                        elseif (!$Pn) {
                            $grepStream.writeline("Host: $outhost`tStatus: Down")
                        }
                    }
                    if ($xmlStream) {
                        $xmlStream.WriteStartElement("Host")

                        $xmlStream.WriteAttributeString("id", $outhost)
                        if (!$PN) {
                            if ($isUp) {
                                $xmlStream.WriteAttributeString("Status", "Up")
                             }
                             else {
                                $xmlStream.WriteAttributeString("Status", "Downs")
                             }
                        }

                        $xmlStream.WriteStartElement("Ports")
                        foreach($p in $openPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "open")
                            $xmlStream.WriteEndElement()

                        }
                        foreach ($p in $closedPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "closed")
                            $xmlStream.WriteEndElement()
                        }
                        foreach ($p in $filteredPorts) {
                            $xmlStream.writestartElement("Port")
                            $xmlStream.WriteAttributeString("id", [string]$p)
                            $xmlStream.WriteAttributeString("state", "filtered")
                            $xmlStream.WriteEndElement()
                        }

                        $xmlStream.WriteEndElement()
                        $xmlStream.WriteEndElement()
                    }
                    if ($readableStream) {
                        $readableStream.writeline("Porscan.ps1 scan report for $outhost")
                        if ($isUp) {
                            $readableStream.writeline("Host is up")
                        }

                        if ($isUp -or $Pn) {

                            $readableStream.writeline(("{0,-10}{1,0}" -f "PORT", "STATE"))

                            [int[]]$allports = $openPorts + $closedPorts + $filteredPorts
                            foreach($p in ($allports| Sort-Object))
                            {
                                if ($openPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "open"))
                                }
                                elseif ($closedPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "closed"))
                                }
                                elseif ($filteredPorts.Contains($p)) {
                                    $readableStream.writeline(("{0,-10}{1,0}" -f $p, "filtered"))
                                }
                            }

                        }
                        elseif(!$Pn) {
                            $readableStream.writeline("Host is Down")
                        }
                        $readableStream.writeline("")
                    }
                }
            }
        }

        #function for Powershell v2.0 to work
        function Convert-SwitchtoBool
        {
            Param (
                [Parameter(Mandatory = $True)] $switchValue
            )
            If ($switchValue) {
                return $True
            }
            return $False
        }


        try
        {

            [bool] $Pn = Convert-SwitchtoBool ($Pn)
            [bool] $sn = Convert-SwitchtoBool ($sn)
            [bool] $q  = Convert-SwitchtoBool ($q)
            [bool] $F  = Convert-SwitchtoBool ($F)

            #########
            #parse arguments
            #########

            if ($Hosts)
            {
                foreach($h in $Hosts)
                {
                    Parse-Hosts($h) | Out-Null
                }
            }
            elseif ($iL)
            {
                Parse-ILHosts($iL) | Out-Null
            }
            if($exclude)
            {
                Exclude-Hosts($exclude)
            }
            if (($topPorts -and $Ports) -or ($topPorts -and $iP))
            {
                throw "Cannot set topPorts with other specific ports"
            }
            if($Ports)
            {
                Parse-Ports -Ports $Ports -pList $portList | Out-Null
            }
            if($iP)
            {
                Parse-IpPorts($iP) | Out-Null
            }
            if($portList.Count -eq 0)
            {
                if ($topPorts)
                {
                    Get-TopPort($topPorts) | Out-Null
                }
                else
                {
                    #if the ports still aren't set, give the deftault, top 50 ports
                    Get-TopPort(50) | Out-Null
                }
            }
            if ($xPorts)
            {
                Remove-Ports -xPorts $xPorts | Out-Null
            }

            if($T)
            {
                switch ($T)
                {
                    5 {$nHosts=40;  $Threads = 1000; $Timeout = 750 }
                    4 {$nHosts=30;  $Threads = 1000; $Timeout = 1200 }
                    3 {$nHosts=25;  $Threads = 100;  $Timeout = 2000 }
                    2 {$nHosts=20;  $Threads = 32;   $Timeout = 2500 }
                    1 {$nHosts=10;  $Threads = 32;   $Timeout = 5000 }
                    default {
                        throw "Invalid T parameter"
                    }
                }
            }

            $grepStream = $null
            $xmlStream = $null
            $readableStream = $null

            if($oA)
            {
                if ($oG -or $oX -or $oN) {
                     Write-Warning "Both -oA specified with other output... going to ignore -oG/-oN/-oX"
                }
                $oG = $oA + ".gnmap"
                $oX = $oA + ".xml"
                $oN = $oA + ".nmap"
            }
            if ($oG) {
                if (!$F -and (Test-Path $oG)) {
                    throw "Error: $oA already exists. Either delete the file or specify the -f flag"
                }
                $grepStream = [System.IO.StreamWriter] $oG
            }
            if ($oN) {
                if (!$F -and (Test-Path $oN)) {
                    throw "Error: $oN already exists. Either delete the file or specify the -f flag"
                }
                $readableStream = [System.IO.StreamWriter] $oN
            }
            if ($oX) {
                if (!$F -and (Test-Path $oX)) {
                    throw "Error: $oX already exists. Either delete the file or specify the -f flag"
                }

                $xmlStream =   [System.xml.xmlwriter]::Create([string]$oX)
                $xmlStream.WriteStartDocument()
                $xmlStream.WriteStartElement("Portscanrun")
                $xmlStream.WriteAttributeString("version", $version)

            }

            Parse-Ports -Ports $PS -pList $hostPortList | Out-Null

            [Environment]::CurrentDirectory=(Get-Location -PSProvider FileSystem).ProviderPath

            $startdate = Get-Date
            $myInvocationLine = $PSCmdlet.MyInvocation.Line
            $startMsg = "Invoke-Portscan.ps1 v$version scan initiated $startdate as: $myInvocationLine"

            Write-PortscanOut -comment $startMsg -quiet $q -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream

            #converting back from int array gives some argument error checking
            $sPortList = [string]::join(",", $portList)
            $sHostPortList = [string]::join(",", $hostPortList)


            ########
            #Port Scan Code - run on a per host basis
            ########
            $portScanCode = {
                param (
                    [Parameter( Mandatory = $True)] [string] $thost,
                    [Parameter( Mandatory = $True)][bool] $Pn,
                    [Parameter( Mandatory = $True)][bool] $sn,
                    [Parameter( Mandatory = $True)][int] $Timeout,
                    [Parameter( Mandatory = $True)] $PortList,
                    [Parameter( Mandatory = $True)] $hostPortList,
                    [Parameter( Mandatory = $True)][int] $maxthreads)
                Process
                {
                $openPorts = New-Object System.Collections.ArrayList
                $closedPorts = New-Object System.Collections.ArrayList
                $filteredPorts = New-Object System.Collections.ArrayList

                $sockets = @{}
                $timeouts = New-Object Hashtable

                #set maximum $async threads
                $fThreads = New-Object int
                $aThreads = New-Object int
                [System.Threading.ThreadPool]::GetMaxThreads([ref]$fThreads, [ref]$aThreads) | Out-Null
                [System.Threading.ThreadPool]::SetMaxThreads($fthreads,$maxthreads) | Out-Null

                function New-ScriptBlockCallback {
                    param(
                        [parameter(Mandatory=$true)]
                        [ValidateNotNullOrEmpty()]
                        [scriptblock]$Callback
                    )

                    #taken from http://www.nivot.org/blog/post/2009/10/09/PowerShell20AsynchronousCallbacksFromNET
                    if (-not ("CallbackEventBridge" -as [type])) {
                        Add-Type @"
                            using System;

                            public sealed class CallbackEventBridge
                            {
                                public event AsyncCallback CallbackComplete = delegate { };

                                private CallbackEventBridge() {}

                                private void CallbackInternal(IAsyncResult result)
                                {
                                    CallbackComplete(result);
                                }

                                public AsyncCallback Callback
                                {
                                    get { return new AsyncCallback(CallbackInternal); }
                                }

                                public static CallbackEventBridge Create()
                                {
                                    return new CallbackEventBridge();
                                }
                            }
"@
                    }

                    $bridge = [CallbackEventBridge]::Create()
                    Register-ObjectEvent -InputObject $bridge -EventName CallbackComplete -Action $Callback | Out-Null

                    $bridge.Callback

                }

                function Test-Port {

                    Param (
                        [Parameter(Mandatory = $True)] [String] $h,
                        [Parameter(Mandatory = $True)] [int] $p,
                        [Parameter(Mandatory = $True)] [int] $timeout
                    )

                    $sockets[$p] = new-object System.Net.Sockets.TcpClient
                    $scriptBlockAsString = @"

                        #somewhat of a race condition with the timeout, but I don't think it matters
                        if ( `$sockets[$p] -ne `$NULL)
                        {
                            if (!`$timeouts[$p].Disposed) {
                                `$timeouts[$p].Dispose()
                            }

                            `$status = `$sockets[$p].Connected;
                            if (`$status -eq `$True)
                            {
                                #write-host "$p is open"
                                `$openPorts.Add($p)
                            }
                            else
                            {
                                #write-host "$p is closed"
                                `$closedPorts.Add($p)

                            }
                            `$sockets[$p].Close();

                            `$sockets.Remove($p)
                        }
"@
                    $timeoutCallback = @"
                        #write-host "$p is filtered"
                        `$sockets[$p].Close()
                        if (!`$timeouts[$p].Disposed) {
                            `$timeouts[$p].Dispose()
                            `$filteredPorts.Add($p)
                        }
                        `$sockets.Remove($p)
"@


                    $timeoutCallback = [scriptblock]::Create($timeoutCallback)

                    $timeouts[$p] = New-Object System.Timers.Timer
                    Register-ObjectEvent -InputObject $timeouts[$p] -EventName Elapsed -Action $timeoutCallback | Out-Null
                    $timeouts[$p].Interval = $timeout
                    $timeouts[$p].Enabled = $true


                    $myscriptblock = [scriptblock]::Create($scriptBlockAsString)
                    $x = $sockets[$p].beginConnect($h, $p,(New-ScriptBlockCallback($myscriptblock)) , $null)

                }

                function PortScan-Alive
                {
                    Param (
                        [Parameter(Mandatory = $True)] [String] $h
                    )

                    Try
                    {

                        #ping
                        if ($hostPortList.Contains(-1))
                        {
                            $ping = new-object System.Net.NetworkInformation.Ping
                            $pResult = $ping.send($h)
                            if ($pResult.Status -eq "Success")
                            {
                                return $True
                            }
                        }
                        foreach($Port in $hostPortList)
                        {
                            if ($Port -ne -1)
                            {
                                Test-Port -h $h -p $Port -timeout $Timeout
                            }
                        }

                        do {
                            if (($openPorts.Count -gt 0) -or ($closedPorts.Count -gt 0)) {
                                return $True
                            }
                            Start-Sleep -Milli 100
                        }
                        While ($sockets.Count -gt 0)

                    }
                    Catch
                    {
                        Write-Error "Exception trying to host scan $h"
                        Write-Error $_.Exception.Message;
                    }

                    return $False
                }

                function Portscan-Port
                {
                    Param (
                        [Parameter(Mandatory = $True)] [String] $h
                    )

                    $openPorts.clear()
                    $closedPorts.clear()
                    $filteredPorts.Clear()

                    [string[]]$Ports = @()


                    foreach($Port in $Portlist)
                    {
                        Try
                        {
                            Test-Port -h $h -p $Port -timeout $Timeout
                        }
                        Catch
                        {
                            Write-Error "Exception trying to scan $h port $Port"
                            Write-Error $_.Exception.Message;
                        }
                    }
                }
                [bool] $hostResult = $False

                if(!$Pn)
                {
                    [bool] $hostResult = PortScan-Alive $thost
                }
                if((!$sn) -and ($hostResult -or $Pn))
                {
                    Portscan-Port $thost
                }
                while ($sockets.Count -gt 0) {
                    Start-Sleep -Milli 500
                }

                return @($hostResult, $openPorts, $closedPorts, $filteredPorts)
                }
            }


            # the outer loop is to flush the loop.
            # Otherwise Get-Job | Wait-Job could clog, etc

            [int]$saveIteration = 0
            [int]$computersDone=0
            [int]$upHosts=0
            while (($saveIteration * $syncFreq) -lt $hostList.Count)
            {

                Get-Job | Remove-Job -Force
                $sIndex = ($saveIteration*$syncFreq)
                $eIndex = (($saveIteration+1)*$syncFreq)-1

                foreach ($iHost in $hostList[$sIndex..$eIndex])
                {
                    $ctr = @(Get-Job -state Running)
                    while ($ctr.Count -ge $nHosts)
                    {
                        Start-Sleep -Milliseconds $sleepTimer
                        $ctr = @(Get-Job -state Running)
                    }

                    $computersDone++
                    if($v)
                    {
                        Write-Progress -status "Port Scanning" -Activity "Port Scan" -CurrentOperation "starting computer $computersDone"  -PercentComplete ($computersDone / $hostList.Count * 100)
                    }

                    Start-Job -ScriptBlock $portScanCode -Name $iHost -ArgumentList @($iHost, $Pn, $sn, $Timeout, $portList, $hostPortList, $Threads)  | Out-Null
                }

                Get-Job | Wait-Job | Out-Null

                foreach ($job in Get-Job)
                {
                    $jobOut = @(Receive-Job $job)
                    [bool]$hostUp = $jobOut[0]
                    $jobName = $job.Name

                    $openPorts = $jobOut[1]
                    $closedPorts = $jobOut[2]
                    $filteredPorts = $jobOut[3]

                    if($hostUp) {
                        $upHosts ++
                    }
                    Write-PortscanOut -outhost $jobName -isUp $hostUp -openPorts $openPorts -closedPorts $closedPorts -filteredPorts $filteredPorts -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream -quiet $q -Pn $Pn
                }

                if ($grepStream) {
                    $grepStream.flush()
                }
                if ($xmlStream) {
                    $xmlStream.flush()
                }
                if($readableStream) {
                    $readableStream.flush()
                }

                $saveIteration ++
            }

            $enddate = Get-Date
            $totaltime = ($enddate - $startdate).TotalSeconds
            $endMsg = "Port scan complete at $enddate ($totaltime seconds)"
            if (!$Pn) {
                $endMsg += ", $upHosts hosts are up"
            }

            Write-PortscanOut -comment $endMsg -quiet $q -grepStream $grepStream -xmlStream $xmlStream -readableStream $readableStream

            if($grepStream) {
                $grepStream.Close()
            }
            if ($xmlStream) {
                $xmlStream.Close()
            }
            if($readableStream) {
                $readableStream.Close()
            }
        }
        Catch
        {
            Write-Error $_.Exception.Message;
        }
    }
}


