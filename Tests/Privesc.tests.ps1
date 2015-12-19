Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."

$ModuleManifest = "$ModuleRoot\Privesc\Privesc.psd1"
Remove-Module [P]rivesc
Import-Module $ModuleManifest -Force -ErrorAction Stop

# import PowerUp.ps1 manually so we expose the helper functions for testing
$PowerUpFile = "$ModuleRoot\Privesc\PowerUp.ps1"
Import-Module $PowerUpFile -Force -ErrorAction Stop



function Get-RandomName {
    $r = 1..8 | ForEach-Object{Get-Random -max 26}
    return ('abcdefghijklmnopqrstuvwxyz'[$r] -join '')
}

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}


########################################################
#
# PowerUp helpers functions.
#
########################################################

Describe 'Get-ModifiableFile' {

    It 'Should output a file path.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        try {
            $Output = Get-ModifiableFile -Path $FilePath
            $Output | Should Be $FilePath
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should extract a modifiable file specified as an argument in a command string.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        $CmdPath = "'C:\Windows\System32\nonexistent.exe' -i '$FilePath'"
        
        try {
            $Output = Get-ModifiableFile -Path $FilePath
            $Output | Should Be $FilePath
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should return no results for a non-existent path.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"

        $Output = Get-ModifiableFile -Path $FilePath
        $Output | Should BeNullOrEmpty
    }

    It 'Should accept a Path over the pipeline.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"

        $Output = $FilePath | Get-ModifiableFile
        $Output | Should BeNullOrEmpty
    }
}


########################################################
#
# PowerUp service enumeration functions.
#
########################################################

Describe 'Get-ServiceUnquoted' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Get-ServicePermission' Pester test needs local administrator privileges."
    }

    It "Should not throw." {
        {Get-ServiceUnquoted} | Should Not Throw
    }

    It 'Should return service with a space in an unquoted binPath.' {

        $ServiceName = Get-RandomName
        $ServicePath = "C:\Program Files\service.exe"

        sc.exe create $ServiceName binPath= $ServicePath | Should Match "SUCCESS"
        Start-Sleep -Seconds 1

        $Output = Get-ServiceUnquoted | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match "SUCCESS"

        $Output | Should Not BeNullOrEmpty
        $Output.ServiceName | Should Be $ServiceName
        $Output.Path | Should Be $ServicePath
    }

    It 'Should not return services with a quoted binPath.' {
        $ServiceName = Get-RandomName
        $ServicePath = "'C:\Program Files\service.exe'"

        sc.exe create $ServiceName binPath= $ServicePath | Should Match "SUCCESS"
        Start-Sleep -Seconds 1

        $Output = Get-ServiceUnquoted | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match "SUCCESS"

        $Output | Should BeNullOrEmpty
    }
}


Describe 'Get-ServiceFilePermission' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Get-ServiceFilePermission' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-ServiceFilePermission} | Should Not Throw
    }

    It 'Should return a service with a modifiable service binary.' {
        try {
            $ServiceName = Get-RandomName
            $ServicePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())" + ".exe"
            $Null | Out-File -FilePath $ServicePath -Force

            sc.exe create $ServiceName binPath= $ServicePath | Should Match "SUCCESS"

            $Output = Get-ServiceFilePermission | Where-Object { $_.ServiceName -eq $ServiceName }
            sc.exe delete $ServiceName | Should Match "SUCCESS"
            
            $Output | Should Not BeNullOrEmpty
            $Output.ServiceName | Should Be $ServiceName
            $Output.Path | Should Be $ServicePath
        }
        finally {
            $Null = Remove-Item -Path $ServicePath -Force
        }
    }

    It 'Should not return a service with a non-existent service binary.' {
        $ServiceName = Get-RandomName
        $ServicePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())" + ".exe"

        sc.exe create $ServiceName binPath= $ServicePath | Should Match "SUCCESS"

        $Output = Get-ServiceFilePermission | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match "SUCCESS"

        $Output | Should BeNullOrEmpty
    }
}


Describe 'Get-ServicePermission' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Get-ServicePermission' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-ServicePermission} | Should Not Throw
    }

    It 'Should return a modifiable service.' {
        $Output = Get-ServicePermission | Where-Object { $_.ServiceName -eq 'Dhcp'}
        $Output | Should Not BeNullOrEmpty
    }
}


Describe 'Get-ServiceDetail' {

    It 'Should return results for a valid service.' {
        $Output = Get-ServiceDetail -ServiceName Dhcp
        $Output | Should Not BeNullOrEmpty
    }

    It 'Should return not results for an invalid service.' {
        $Output = Get-ServiceDetail -ServiceName NonExistent123
        $Output | Should BeNullOrEmpty
    }

    It 'Should accept a service name on the pipeline.' {
        $Output = "Dhcp" | Get-ServiceDetail
        $Output | Should Not BeNullOrEmpty
    }
}



########################################################
#
# PowerUp service abuse functions.
#
########################################################

Describe 'Invoke-ServiceAbuse' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Invoke-ServiceAbuse' Pester test needs local administrator privileges."
    }

    BeforeEach {
        $ServicePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())" + ".exe"
        $Null = sc.exe create "PowerUpService" binPath= $ServicePath
    }

    AfterEach {
        $Null = sc.exe delete "PowerUpService"
        $Null = $(net user john /delete >$Null 2>&1)
    }

    It 'Should abuse a vulnerable service to add a local administrator with default options.' {
        $Output = Invoke-ServiceAbuse -ServiceName "PowerUpService"
        $Output.Command | Should Match "net"

        if( -not ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' not created."
        }
    }

    It 'Should accept a service name on the pipeline.' {
        $Output = "PowerUpService" | Invoke-ServiceAbuse
        $Output.Command | Should Match "net"

        if( -not ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' not created."
        }
    }

    It 'User should not be created for a non-existent service.' {
        $Output = Invoke-ServiceAbuse -ServiceName "NonExistentService456"
        $Output.Command | Should Match "Not found"

        if( ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' should not have been created for non-existent service."
        }
    }

    It 'Should accept custom user/password arguments.' {
        $Output = Invoke-ServiceAbuse -ServiceName "PowerUpService" -Username PowerUp -Password 'PASSword123!'
        $Output.Command | Should Match "net"

        if( -not ($(net localgroup Administrators) -match "PowerUp")) {
            Throw "Local user 'PowerUp' not created."
        }
        $Null = $(net user PowerUp /delete >$Null 2>&1)
    }

    It 'Should accept a custom command.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Output = Invoke-ServiceAbuse -ServiceName "PowerUpService" -Command "net user testing Password123! /add"

        if( -not ($(net user) -match "testing")) {
            Throw "Custom command failed."
        }
        $Null = $(net user testing /delete >$Null 2>&1)
    }
}


Describe 'Install-ServiceBinary' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Install-ServiceBinary' Pester test needs local administrator privileges."
    }

    BeforeEach {
        $ServicePath = "$(Get-Location)\powerup.exe"
        $Null | Out-File -FilePath $ServicePath -Force
        $Null = sc.exe create "PowerUpService" binPath= $ServicePath
    }

    AfterEach {
        try {
            $Null = Invoke-ServiceStop -ServiceName PowerUpService
            $Null = sc.exe delete "PowerUpService"
            $Null = $(net user john /delete >$Null 2>&1)
        }
        finally {
            if(Test-Path "$(Get-Location)\powerup.exe") {
                $Null = Remove-Item -Path "$(Get-Location)\powerup.exe" -Force -ErrorAction SilentlyContinue
            }
            if(Test-Path "$(Get-Location)\powerup.exe.bak") {
                $Null = Remove-Item -Path "$(Get-Location)\powerup.exe.bak" -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'Should abuse a vulnerable service binary to add a local administrator with default options.' {

        $Output = Install-ServiceBinary -ServiceName "PowerUpService"
        $Output.Command | Should Match "net"

        $Null = Invoke-ServiceStart -ServiceName PowerUpService
        Start-Sleep -Seconds 3
        if( -not ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' not created."
        }
        $Null = Invoke-ServiceStop -ServiceName PowerUpService

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'Should accept a service name on the pipeline.' {

        $Output = "PowerUpService" | Install-ServiceBinary
        $Output.Command | Should Match "net"

        $Null = Invoke-ServiceStart -ServiceName PowerUpService
        Start-Sleep -Seconds 3
        if( -not ($(net localgroup Administrators) -match "john")) {
            Throw "Local user 'john' not created."
        }
        $Null = Invoke-ServiceStop -ServiceName PowerUpService

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'User should not be created for a non-existent service.' {
        $Output = Install-ServiceBinary -ServiceName "NonExistentService456"
        $Output.Command | Should Match "Not found"
    }

    It 'Should accept custom user/password arguments.' {
        $Output = Install-ServiceBinary -ServiceName "PowerUpService" -Username PowerUp -Password 'PASSword123!'
        $Output.Command | Should Match "net"

        $Null = Invoke-ServiceStart -ServiceName PowerUpService
        Start-Sleep -Seconds 3
        if( -not ($(net localgroup Administrators) -match "PowerUp")) {
            Throw "Local user 'PowerUp' not created."
        }
        $Null = $(net user PowerUp /delete >$Null 2>&1)

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'Should accept a custom command.' {

        $Output = Install-ServiceBinary -ServiceName "PowerUpService" -Command "net user testing Password123! /add"
        $Output.Command | Should Match "net"

        $Null = Invoke-ServiceStart -ServiceName PowerUpService
        Start-Sleep -Seconds 3
        if( -not ($(net user) -match "testing")) {
            Throw "Custom command failed."
        }
        $Null = $(net user testing /delete >$Null 2>&1)

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }
}


########################################################
#
# PowerUp .dll hijacking functions.
#
########################################################

Describe 'Find-DLLHijack' {
    It 'Should return results.' {
        $Output = Find-DLLHijack
        $Output | Should Not BeNullOrEmpty
    }
}


Describe 'Find-PathHijack' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Find-PathHijack' Pester test needs local administrator privileges."
    }

    It 'Should find a hijackable %PATH% folder.' {

        New-Item -Path C:\PowerUpTest\ -ItemType directory -Force

        try {
            $OldPath = $Env:PATH
            $Env:PATH += ';C:\PowerUpTest\'

            $Output = Find-PathHijack | Where-Object {$_.HijackablePath -like "*PowerUpTest*"}

            $Env:PATH = $OldPath
            $Output.HijackablePath | Should Be 'C:\PowerUpTest\'
        }
        catch {
            $Null = Remove-Item -Recurse -Force 'C:\PowerUpTest\' -ErrorAction SilentlyContinue
        }
    }
}

# won't actually execute on Win8+ with the wlbsctrl.dll method
Describe 'Write-HijackDll' {

    It 'Should write a .dll that executes a custom command.' {

        try {
            Write-HijackDll -OutputFile "$(Get-Location)\powerup.dll" -Command "net user testing Password123! /add"
            
            "$(Get-Location)\powerup.dll" | Should Exist
            "$(Get-Location)\debug.bat" | Should Exist
        }
        finally {
            $Null = Remove-Item -Path "$(Get-Location)\powerup.dll" -Force -ErrorAction SilentlyContinue
            $Null = Remove-Item -Path "$(Get-Location)\debug.bat" -Force -ErrorAction SilentlyContinue
        }
    }
}


########################################################
#
# PowerUp registry checks.
#
########################################################

Describe 'Get-RegAlwaysInstallElevated' {
    It 'Should not throw.' {
        {Get-ServicePermission} | Should Not Throw
    }
}


Describe 'Get-RegAutoLogon' {
    It 'Should not throw.' {
        {Get-ServicePermission} | Should Not Throw
    }
}


Describe 'Get-VulnAutoRun' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Get-VulnAutoRun' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-VulnAutoRun} | Should Not Throw
    }
    It 'Should find a vulnerable autorun.' {
        try {
            $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
            $Null | Out-File -FilePath $FilePath -Force
            $Null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name PowerUp -Value "vuln.exe -i '$FilePath'"

            $Output = Get-VulnAutoRun | ?{$_.Path -like "*$FilePath*"}

            $Null = Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name PowerUp
            
            $Output.ModifiableFile | Should Be $FilePath
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }    
}


########################################################
#
# PowerUp misc. checks.
#
########################################################

Describe 'Get-VulnSchTask' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Get-VulnSchTask' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-VulnSchTask} | Should Not Throw
    }

    It 'Should find a vulnerable config file for a binary specified in a schtask.' {

        try {
            $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
            $Null | Out-File -FilePath $FilePath -Force

            $Null = schtasks.exe /create /tn PowerUp /tr "vuln.exe -i '$FilePath'" /sc onstart /ru System /f

            $Output = Get-VulnSchTask | Where-Object {$_.TaskName -eq 'PowerUp'}
            $Null = schtasks.exe /delete /tn PowerUp /f
            
            $Output.TaskFilePath | Should Be $FilePath
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }
}


Describe 'Get-UnattendedInstallFile' {

    if(-not $(Test-IsAdmin)) { 
        Throw "'Get-UnattendedInstallFile' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-UnattendedInstallFile} | Should Not Throw
    }
    It 'Should return a leftover autorun' {
        $FilePath = Join-Path $Env:WinDir "\System32\Sysprep\unattend.xml"

        try {
            $Null | Out-File -FilePath $FilePath -Force
            $Output = Get-UnattendedInstallFile

            $Output | Should Not BeNullOrEmpty
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }
}


Describe 'Get-Webconfig' {
    It 'Should not throw.' {
        {Get-Webconfig} | Should Not Throw
    }
}


Describe 'Get-ApplicationHost' {
    It 'Should not throw.' {
        {Get-ApplicationHost} | Should Not Throw
    }
}


Describe 'Invoke-AllChecks' {
    It 'Should return results to stdout.' {
        $Output = Invoke-AllChecks
        $Output | Should Not BeNullOrEmpty
    }
    It 'Should produce a HTML report with -HTMLReport.' {
        $Output = Invoke-AllChecks -HTMLReport
        $Output | Should Not BeNullOrEmpty

        $HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"

        $HtmlReportFile | Should Exist
        $Null = Remove-Item -Path $HtmlReportFile -Force -ErrorAction SilentlyContinue
    }
}
