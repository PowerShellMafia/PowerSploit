Get-ChildItem (Join-Path $PSScriptRoot *.ps1) | ? {$_.Name -ne 'Invoke-Shellcode.ps1'} | % { . $_.FullName}
