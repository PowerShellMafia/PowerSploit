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
    
    $KeyLogger = Get-Keystrokes -PassThru
    Start-Sleep -Seconds 1

    $Shell.SendKeys("Pester`b`b`b`b`b`b")
    $KeyLogger.Dispose()

    It 'Should output to file' { Test-Path "$($env:TEMP)\key.log" | Should Be $true }

    It 'Should log keystrokes' {
        $FileLength = (Get-Item "$($env:TEMP)\key.log").Length
        $FileLength | Should BeGreaterThan 14
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
        $KeyLogger = Get-Keystrokes -Timeout $Timeout -PassThru
        
        Start-Sleep -Seconds 4

        $KeyLogger.Runspace.RunspaceAvailability | Should Be 'Available'
        $KeyLogger.Dispose()
    }

    Remove-Item -Force "$($env:TEMP)\key.log"
}
