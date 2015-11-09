Get-ChildItem $PSScriptRoot | ? { $_.PSIsContainer -and ($_.Name -ne 'Tests') } | % { Import-Module $_.FullName -DisableNameChecking }
