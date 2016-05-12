Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."
$ModuleManifest = "$ModuleRoot\Exfiltration\Exfiltration.psd1"

Remove-Module [E]xfiltration
Import-Module $ModuleManifest -Force -ErrorAction Stop

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
