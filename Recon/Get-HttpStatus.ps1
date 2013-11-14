function Get-HttpStatus
{
<#
.SYNOPSIS

Returns the HTTP Status Codes and full URL for specified paths.

PowerSploit Function: Get-HttpStatus
Author: Chris Campbell (@obscuresec)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

A script to check for the existence of a path or file on a webserver.

.PARAMETER Target

Specifies the remote web host either by IP or hostname.

.PARAMETER Path

Specifies the remost host.

.PARAMETER Port

Specifies the port to connect to.

.PARAMETER UseSSL

Use an SSL connection.

.EXAMPLE

C:\PS> Get-HttpStatus -Target www.example.com -Path c:\dictionary.txt | Select-Object {where StatusCode -eq 20*}

.EXAMPLE

C:\PS> Get-HttpStatus -Target www.example.com -Path c:\dictionary.txt -UseSSL

.NOTES

HTTP Status Codes: 100 - Informational * 200 - Success * 300 - Redirection * 400 - Client Error * 500 - Server Error
    
.LINK

http://obscuresecurity.blogspot.com
http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html
#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [String]
        $Target,

        [String]
        [ValidateNotNullOrEmpty()]
        $Path = '.\Dictionaries\admin.txt',

        [Int]
        $Port,

        [Switch]
        $UseSSL
    )
    
    if (Test-Path $Path) {
    
        if ($UseSSL -and $Port -eq 0) {
            # Default to 443 if SSL is specified but no port is specified
            $Port = 443
        } elseif ($Port -eq 0) {
            # Default to port 80 if no port is specified
            $Port = 80
        }
    
        $TcpConnection = New-Object System.Net.Sockets.TcpClient
        Write-Verbose "Path Test Succeeded - Testing Connectivity"
        
        try {
            # Validate that the host is listening before scanning
            $TcpConnection.Connect($Target, $Port)
        } catch {
            Write-Error "Connection Test Failed - Check Target"
            $Tcpconnection.Close()
            Return 
        }
        
        $Tcpconnection.Close()
    } else {
           Write-Error "Path Test Failed - Check Dictionary Path"
           Return
    }
    
    if ($UseSSL) {
        $SSL = 's'
        # Ignore invalid SSL certificates
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
    } else {
        $SSL = ''
    }
    
    if (($Port -eq 80) -or ($Port -eq 443)) {
        $PortNum = ''
    } else {
        $PortNum = ":$Port"
    }
    
    # Check Http status for each entry in the doctionary file
    foreach ($Item in Get-Content $Path) {

        $WebTarget = "http$($SSL)://$($Target)$($PortNum)/$($Item)"
        $URI = New-Object Uri($WebTarget)

        try {
            $WebRequest = [System.Net.WebRequest]::Create($URI)
            $WebResponse = $WebRequest.GetResponse()
            $WebStatus = $WebResponse.StatusCode
            $ResultObject += $ScanObject
            $WebResponse.Close()
        } catch {
            $WebStatus = $Error[0].Exception.InnerException.Response.StatusCode
            
            if ($WebStatus -eq $null) {
                # Not every exception returns a StatusCode.
                # If that is the case, return the Status.
                $WebStatus = $Error[0].Exception.InnerException.Status
            }
        } 
        
        $Result = @{ Status = $WebStatus;
                     URL = $WebTarget}
        
        $ScanObject = New-Object -TypeName PSObject -Property $Result
        
        Write-Output $ScanObject
        
    }
}
