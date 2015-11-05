Set-StrictMode -Version Latest

$TestScriptRoot = Split-Path $MyInvocation.MyCommand.Path -Parent
$ModuleRoot = Resolve-Path "$TestScriptRoot\.."

filter Assert-NotLittleEndianUnicode {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True,
                   ValueFromPipelineByPropertyName = $True,
                   ValueFromPipeline = $True)]
        [Alias('FullName')]
        [String[]]
        $FilePath
    )

    $LittleEndianMarker = 48111 # 0xBBEF

    Write-Verbose "Current file: $FilePath"
    Write-Debug "Current file: $FilePath"

    if ([System.IO.Directory]::Exists($FilePath)) {
        Write-Debug "File is a directory."
        return
    }

    if (-not [System.IO.File]::Exists($FilePath)) {
        Write-Debug "File does not exist."
        return
    }

    $FileBytes = Get-Content -TotalCount 3 -Encoding Byte -Path $FilePath

    if ($FileBytes.Length -le 2) {
        Write-Debug "File must be at least 2 bytes in length."
        return
    }

    if ([BitConverter]::ToUInt16($FileBytes, 0) -eq $LittleEndianMarker) {
        Write-Debug "File contains little endian unicode marker."
        throw "$_ is little-endian unicode encoded."
    }
}

Describe 'ASCII encoding of all scripts' {
	It 'should not contain little-endian unicode encoded scripts or modules' {
		{ Get-ChildItem -Path $ModuleRoot -Recurse -Include *.ps1,*.psd1,*.psm1 | Assert-NotLittleEndianUnicode } | Should Not Throw
	}
}