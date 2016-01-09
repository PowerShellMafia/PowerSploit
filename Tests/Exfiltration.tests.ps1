Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ModuleManifest = "$ModuleRoot\Exfiltration\Exfiltration.psd1"

Remove-Module [E]xfiltration
Import-Module $ModuleManifest -Force -ErrorAction Stop

Describe 'Get-Keystrokes' {
    
    if (Test-Path "$($env:TEMP)\key.log") { Remove-Item -Force "$($env:TEMP)\key.log" }
    $WindowTitle = (Get-Process -Id $PID).MainWindowTitle
    
    $Shell = New-Object -ComObject wscript.shell
    $Shell.AppActivate($WindowTitle)
    
    $KeyLogger = Get-Keystrokes -Return
    Start-Sleep -Seconds 1

    $Shell.SendKeys('Pester is SUPER l337!')
    $KeyLogger.Dispose()

    It 'Should output to file' { Test-Path "$($env:TEMP)\key.log" | Should Be $true }
    
    $KeyObjects = Get-Content -Path "$($env:TEMP)\key.log" | ConvertFrom-Csv

    It 'Should log all keystrokes' {
        $Keys = $KeyObjects | % { $_.TypedKey }
        $String = -join $Keys
        $String | Should Be '<Shift>Pester< >is< ><Shift>S<Shift>U<Shift>P<Shift>E<Shift>R< >l337<Shift>!'
    }

    It 'Should get foreground window title' {
        $KeyObjects[0].WindowTitle | Should Be $WindowTitle
    }

    It 'Should log time of key press' {
        $KeyTime = [DateTime]::Parse($KeyObjects[0].Time)
        $KeyTime.GetType().Name | Should Be 'DateTime'
    }

    It 'Should stop logging after timeout' {
        
        $Timeout = 0.05
        $KeyLogger = Get-Keystrokes -Timeout $Timeout -Return
        
        Start-Sleep -Seconds 4

        $KeyLogger.Runspace.RunspaceAvailability | Should Be 'Available'
        $KeyLogger.Dispose()
    }

    Remove-Item -Force "$($env:TEMP)\key.log"
}
