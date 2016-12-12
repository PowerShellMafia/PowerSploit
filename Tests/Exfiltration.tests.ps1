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
    
    $KeyObjects = Get-Content -Path "$($env:TEMP)\key.log" | ConvertFrom-Csv

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

Describe "Get-MicrophoneAudio" {

	$RecordPath = "$env:TEMP\test_record.wav"
	$RecordLen = 2
	Context 'Successful Recording' {
		BeforeEach { 
			#Ensure the recording as been removed prior to testing
			Remove-Item -Path $RecordPath -ErrorAction SilentlyContinue
		}

		AfterEach {
			#Remove the recording after testing
			Remove-Item -Path $RecordPath -ErrorAction SilentlyContinue
		}

		It 'should record audio from the microphone and save it to a specified path' {
			$result = Get-MicrophoneAudio -Path $RecordPath -Length $RecordLen
			$result | Should Not BeNullOrEmpty
			$result.Length | Should BeGreaterThan 0
		}

	}

	Context 'Invalid Arguments' {
		It 'should not allow invalid paths to be used' {
			{ Get-MicrophoneAudio -Path "c:\FAKEPATH\yay.wav" -Length RecordLen} | Should Throw
		}
	}

}
