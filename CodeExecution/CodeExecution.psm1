Get-ChildItem (Join-Path $PSScriptRoot *.ps1) | % { . $_.FullName}
