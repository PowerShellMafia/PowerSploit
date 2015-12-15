
$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ModuleManifest = "$ModuleRoot\Recon\Recon.psd1"

Remove-Module [R]econ
Import-Module $ModuleManifest -Force -ErrorAction Stop

# import PowerView.ps1 manually so we expose the helper functions for testing
$PowerViewFile = "$ModuleRoot\Recon\PowerView.ps1"
Import-Module $PowerViewFile -Force -ErrorAction Stop


# Get the local IP address for later testing
$IPregex = "(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
$LocalIP = (gwmi Win32_NetworkAdapterConfiguration | ? { $_.IPAddress -match $IPregex}).ipaddress[0]


########################################################
#
# PowerView functions.
#
########################################################

Describe 'Export-PowerViewCSV' {
    It 'Should Not Throw and should produce .csv output.' {
        {Get-Process | Export-PowerViewCSV -OutFile process_test.csv} | Should Not Throw
        '.\process_test.csv' | Should Exist
        Remove-Item -Force .\process_test.csv        
    }
}


Describe 'Set-MacAttribute' {
    BeforeEach {
        New-Item MacAttribute.test.txt -Type file
    }
    AfterEach {
        Remove-Item -Force MacAttribute.test.txt
    }
    It 'Should clone MAC attributes of existing file' {
        Set-MacAttribute -FilePath MacAttribute.test.txt -All '01/01/2000 12:00 am'
        $File = (Get-Item MacAttribute.test.txt)
        $Date = Get-Date -Date '2000-01-01 00:00:00'
        
        if ($File.LastWriteTime -ne $Date) {
            Throw 'File LastWriteTime does Not match'
        }
        elseif($File.LastAccessTime -ne $Date) {
            Throw 'File LastAccessTime does Not match'
        }
        elseif($File.CreationTime -ne $Date) {
            Throw 'File CreationTime does Not match'
        }
    }
}


Describe 'Get-IPAddress' {
    $IPregex = "(?<Address>((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))"
    It 'Should return local IP address' {
        if( $(Get-IPAddress) -notmatch $IPRegex ) {
            Throw 'Invalid local IP address returned'
        }
    }
    It 'Should accept -ComputerName argument' {
        if( $(Get-IPAddress -ComputerName $env:COMPUTERNAME) -notmatch $IPRegex ) {
            Throw 'Invalid -ComputerName IP address returned'
        }
    }
}

Describe 'Convert-SidToName' {
    It 'Should resolve built in SIDs' {
        Convert-SidToName -SID 'S-1-5-32-545' | Should Be 'BUILTIN\Users'
    }
    It 'Should accept pipeline input' {
        'S-1-5-32-552' | Convert-SidToName | Should Be 'BUILTIN\Replicators'
    }
    It 'Should return a unresolvable SID' {
        Convert-SidToName -SID 'S-1-5-32-1337' | Should Be 'S-1-5-32-1337'
    }
}


Describe 'Get-Proxy' {
    It 'Should Not Throw' {
        {Get-Proxy} | Should Not Throw
    }
    It 'Should accept -ComputerName argument' {
        {Get-Proxy -ComputerName $env:COMPUTERNAME} | Should Not Throw
    }   
}


Describe 'Get-PathAcl' {
    It 'Should Not Throw' {
        {Get-PathAcl C:\} | Should Not Throw
    }
    It 'Should return correct ACLs' {
        $Output = Get-PathAcl -Path C:\Windows | ?{$_.IdentityReference -eq "Creator Owner"}
        if(-not $Output) {
            Throw "Output Not returned"
        }
        if($Output.FileSystemRights -ne 'GenericAll') {
            Throw "Incorrect FileSystemRights returned"
        }
    }
}


Describe 'Get-NameField' {
    It 'Should extract dnshostname field from custom object' {
        $Object = New-Object -TypeName PSObject -Property @{'dnshostname' = 'testing1'}
        if ( (Get-NameField -Object $Object) -ne 'testing1') {
            Throw "'dnshostname' field Not parsed correctly"
        }
    }
    It 'Should extract name field from custom object' {
        $Object = New-Object -TypeName PSObject -Property @{'name' = 'testing2'}
        if ( (Get-NameField -Object $Object) -ne 'testing2') {
            Throw "'name' field Not parsed correctly"
        }
    } 
    It 'Should handle plaintext strings' {
        if ( (Get-NameField -Object 'testing3') -ne 'testing3') {
            Throw 'Plaintext string Not parsed correctly'
        }
    } 
    It 'Should accept pipeline input' {
        $Object = New-Object -TypeName PSObject -Property @{'dnshostname' = 'testing4'}
        if ( ($Object | Get-NameField) -ne 'testing4') {
            Throw 'Pipeline input Not processed correctly'
        }
    }
}


Describe 'Invoke-ThreadedFunction' {
    It "Should allow threaded ping" {
        $Hosts = ,"localhost" * 100
        $Ping = {param($ComputerName) if(Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction Stop){$ComputerName}}
        $Hosts = Invoke-ThreadedFunction -NoImports -ComputerName $Hosts -ScriptBlock $Ping -Threads 20
        if($Hosts.length -ne 100) {
            Throw 'Error in using Invoke-ThreadedFunction to ping localhost'
        }
    }
}


Describe "Get-NetLocalGroup" {
    It "Should return results for local machine administrators" {
        if ( (Get-NetLocalGroup | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should return results for listing local groups" {
        if ( (Get-NetLocalGroup -ListGroups | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    # TODO: -ComputerList
    It "Should accept -GroupName argument" {
        {Get-NetLocalGroup -GroupName "Remote Desktop Users"} | Should Not Throw
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetLocalGroup -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetLocalGroup -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( "$env:computername" | Get-NetLocalGroup | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
}


Describe "Get-NetShare" {
    It "Should return results for the local host" {
        if ( (Get-NetShare | Measure-Object).count -lt 1) {
            Throw "Incorrect share results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetShare -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetShare -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect share results returned"
        }
    }
    It "Should accept pipeline input" {
        if ( ( "$env:computername" | Get-NetShare | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
}


Describe "Get-NetLoggedon" {
    It "Should return results for the local host" {
        if ( (Get-NetLoggedon | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetLoggedon -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetLoggedon -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }        
    }
    It "Should accept pipeline input" {
        if ( ( "$env:computername" | Get-NetLoggedon | Measure-Object).count -lt 1) {
            Throw "Incorrect local administrators returned"
        }
    }
}


Describe "Get-NetSession" {
    It "Should return results for the local host" {
        if ( (Get-NetSession | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetSession -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetSession -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept the -UserName argument" {
        {Get-NetSession -UserName 'Administrator'} | Should Not Throw
    }
    It "Should accept pipeline input" {
        {"$env:computername" | Get-NetSession} | Should Not Throw
    }
}


Describe "Get-NetRDPSession" {
    It "Should return results for the local host" {
        if ( (Get-NetRDPSession | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetRDPSession -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetRDPSession -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect session results returned"
        }
    }
    It "Should accept pipeline input" {
        {"$env:computername" | Get-NetRDPSession} | Should Not Throw
    }
}


Describe "Invoke-CheckLocalAdminAccess" {
    It "Should Not Throw for localhost" {
        {Invoke-CheckLocalAdminAccess} | Should Not Throw
    }
    It "Should accept NETBIOS -ComputerName argument" {
        {Invoke-CheckLocalAdminAccess -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept IP -ComputerName argument" {
        {Invoke-CheckLocalAdminAccess -ComputerName $LocalIP} | Should Not Throw
    }
    It "Should accept pipeline input" {
        {"$env:computername" | Invoke-CheckLocalAdminAccess} | Should Not Throw
    }
}


Describe "Get-LastLoggedOn" {
    It "Should return results for the local host" {
        if ( (Get-LastLoggedOn | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-LastLoggedOn -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-LastLoggedOn -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect loggedon results returned"
        }
    }
    It "Should accept pipeline input" {
        {"$env:computername" | Get-LastLoggedOn} | Should Not Throw
    }
}


Describe "Get-CachedRDPConnection" {
    It "Should Not Throw" {
        {Get-CachedRDPConnection} | Should Not Throw
    }
    It "Should accept NETBIOS -ComputerName argument" {
        {Get-CachedRDPConnection -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept IP -ComputerName argument" {
        {Get-CachedRDPConnection -ComputerName $LocalIP} | Should Not Throw
    }
    It "Should accept pipeline input" {
        {"$env:computername" | Get-CachedRDPConnection} | Should Not Throw
    }
}


Describe "Get-NetProcess" {
    It "Should return results for the local host" {
        if ( (Get-NetProcess | Measure-Object).count -lt 1) {
            Throw "Incorrect process results returned"
        }
    }
    It "Should accept NETBIOS -ComputerName argument" {
        if ( (Get-NetProcess -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Incorrect process results returned"
        }
    }
    It "Should accept IP -ComputerName argument" {
        if ( (Get-NetProcess -ComputerName $LocalIP | Measure-Object).count -lt 1) {
            Throw "Incorrect process results returned"
        }
    }
    # TODO: RemoteUserName/RemotePassword
    It "Should accept pipeline input" {
        {"$env:computername" | Get-NetProcess} | Should Not Throw
    }
}


Describe "Find-InterestingFile" {
    #TODO: implement
}


Describe "Invoke-UserHunter" {
    It "Should accept -ComputerName argument" {
        if ( (Invoke-UserHunter -ShowAll -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    try {
        It "Should accept -ComputerFile argument" {
            "$env:computername","$env:computername" | Out-File -Encoding ASCII targets.txt
            if ( (Invoke-UserHunter -ComputerFile ".\targets.txt" -ShowAll | Measure-Object).count -lt 1) {
                Throw "Insuffient results returned"
            }
        }
    }
    finally {
        Remove-Item -Force ".\targets.txt"
    }
    It "Should accept -NoPing flag" {
        if ( (Invoke-UserHunter -ComputerName "$env:computername" -UserName $env:USERNAME -NoPing | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Invoke-UserHunter -ShowAll -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername", "$env:computername") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
}


Describe "Invoke-StealthUserHunter" {
    # simple test of the splatting
    It "Should accept splatting for Invoke-UserHunter" {
        {Invoke-StealthUserHunter -ShowAll -ComputerName "$env:computername"} | Should Not Throw
    }
}


Describe "Invoke-ProcessHunter" {
    It "Should accept -ComputerName and -UserName arguments" {
        if ( (Invoke-ProcessHunter -UserName $env:USERNAME -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    try {
        It "Should accept -ComputerFile argument" {
            "$env:computername","$env:computername" | Out-File -Encoding ASCII targets.txt
            if ( (Invoke-ProcessHunter -ComputerFile ".\targets.txt" -UserName $env:USERNAME | Measure-Object).count -lt 1) {
                Throw "Insuffient results returned"
            }
        }
    }
    finally {
        Remove-Item -Force ".\targets.txt"
    }
    It "Should accept -ProcessName argument" {
        if ( (Invoke-ProcessHunter -ComputerName "$env:computername" -ProcessName powershell | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    try {
        It "Should accept -UserFile argument" {
            "$env:USERNAME" | Out-File -Encoding ASCII target_users.txt
            if ( (Invoke-ProcessHunter -ComputerName "$env:computername" -UserFile ".\target_users.txt" | Measure-Object).count -lt 1) {
                Throw "Insuffient results returned"
            }
        }
    }
    finally {
        Remove-Item -Force ".\target_users.txt"
    }
    It "Should accept -NoPing flag" {
        if ( (Invoke-ProcessHunter -ComputerName "$env:computername" -UserName $env:USERNAME -NoPing | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Invoke-ProcessHunter -UserName $env:USERNAME -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername", "$env:computername") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
}


Describe "Invoke-ShareFinder" {
    It "Should accept -ComputerName argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    try {
        It "Should accept -ComputerFile argument" {
            "$env:computername","$env:computername" | Out-File -Encoding ASCII targets.txt
            if ( (Invoke-ShareFinder -ComputerFile ".\targets.txt" | Measure-Object).count -lt 1) {
                Throw "Insuffient results returned"
            }
        }
    }
    finally {
        Remove-Item -Force ".\targets.txt"
    }
    It "Should accept -ExcludeStandard argument" {
        {Invoke-ShareFinder -ComputerName "$env:computername" -ExcludeStandard} | Should Not Throw
    }
    It "Should accept -ExcludePrint argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername" -ExcludePrint | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -ExcludeIPC argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername" -ExcludeIPC | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -CheckShareAccess argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername" -CheckShareAccess | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -CheckAdmin argument" {
        if ( (Invoke-ShareFinder -ComputerName "$env:computername" -CheckAdmin | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -NoPing argument" {
        if ( (Invoke-ShareFinder -NoPing -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Invoke-ShareFinder -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername", "$env:computername") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
}


Describe "Invoke-FileFinder" {
    It "Should accept -ComputerName argument" {
        {Invoke-FileFinder -ComputerName "$env:computername"} | Should Not Throw
    }
    try {
        It "Should accept -ComputerFile argument" {
            "$env:computername","$env:computername" | Out-File -Encoding ASCII targets.txt        
            {Invoke-FileFinder -ComputerFile ".\targets.txt"} | Should Not Throw
        }
    }
    finally {
        Remove-Item -Force ".\targets.txt"
    }
    try {
        It "Should accept -ShareList argument" {
            "\\$($env:computername)\\IPC$" | Out-File -Encoding ASCII shares.txt
            {Invoke-FileFinder -ShareList ".\shares.txt"} | Should Not Throw
        }
    }
    finally {
        Remove-Item -Force ".\shares.txt"
    }
    It "Should accept -Terms argument" {
        {Invoke-FileFinder -Terms secret,testing -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -OfficeDocs argument" {
        {Invoke-FileFinder -OfficeDocs -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -FreshEXEs argument" {
        {Invoke-FileFinder -FreshEXEs -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -LastAccessTime argument" {
        {Invoke-FileFinder -LastAccessTime "01/01/2000" -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -LastWriteTime argument" {
        {Invoke-FileFinder -LastWriteTime "01/01/2000" -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -ExcludeFolders argument" {
        {Invoke-FileFinder -ExcludeFolders -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -ExcludeHidden argument" {
        {Invoke-FileFinder -ExcludeHidden -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -CreationTime argument" {
        {Invoke-FileFinder -CreationTime "01/01/2000" -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -OutFile argument" {
        {Invoke-FileFinder -ComputerName "$env:computername" -OutFile "found_files.csv"} | Should Not Throw
        if(Test-Path -Path .\found_files.csv) {
            $Null = Remove-Item -Force .\found_files.csv
        }
    }
    It "Should accept -NoPing argument" {
        {Invoke-FileFinder -NoPing -ComputerName "$env:computername"} | Should Not Throw
    }
    It "Should accept -Delay and -Jitter arguments" {
        {Invoke-FileFinder -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername","$env:computername")} | Should Not Throw
    }
}


Describe "Find-LocalAdminAccess" {
    It "Should accept -ComputerName argument" {
        if ( (Find-LocalAdminAccess -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    try {
        It "Should accept -ComputerFile argument" {
            "$env:computername","$env:computername" | Out-File -Encoding ASCII targets.txt
            if ( (Find-LocalAdminAccess -ComputerFile ".\targets.txt" | Measure-Object).count -lt 1) {
                Throw "Insuffient results returned"
            }
        }
    }
    finally {
        Remove-Item -Force ".\targets.txt"
    }
    It "Should accept -NoPing argument" {
        if ( (Find-LocalAdminAccess -NoPing -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Find-LocalAdminAccess -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername","$env:computername") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
}


Describe "Invoke-EnumerateLocalAdmin" {
    It "Should accept -ComputerName argument" {
        if ( (Invoke-EnumerateLocalAdmin -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    try {
        It "Should accept -ComputerFile argument" {
            "$env:computername","$env:computername" | Out-File -Encoding ASCII targets.txt
            if ( (Invoke-EnumerateLocalAdmin -ComputerFile ".\targets.txt" | Measure-Object).count -lt 1) {
                Throw "Insuffient results returned"
            }
        }
    }
    finally {
        Remove-Item -Force ".\targets.txt"
    }
    It "Should accept -NoPing argument" {
        if ( (Invoke-EnumerateLocalAdmin -NoPing -ComputerName "$env:computername" | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Delay and -Jitter arguments" {
        if ( (Invoke-EnumerateLocalAdmin -Delay 5 -Jitter 0.2 -ComputerName @("$env:computername","$env:computername") | Measure-Object).count -lt 1) {
            Throw "Insuffient results returned"
        }
    }
    It "Should accept -Outfile argument" {
        Invoke-EnumerateLocalAdmin -ComputerName "$env:computername" -OutFile "local_admins.csv"
        ".\local_admins.csv" | Should Exist
        Remove-Item -Force .\local_admins.csv
    }
}
