# Make sure the module is not loaded
Remove-Module PowerSploit -ErrorAction SilentlyContinue
# Download latest version
$webclient = New-Object System.Net.WebClient
$url = "https://github.com/PowerShellMafia/PowerSploit/archive/master.zip"
Write-Host "Downloading latest version of PowerSploit from $url" -ForegroundColor Cyan
$file = "$($env:TEMP)\PowerSploit.zip"
$webclient.DownloadFile($url,$file)
Write-Host "File saved to $file" -ForegroundColor Green
# Unblock and Decompress
Unblock-File -Path $file
$targetondisk = "$([System.Environment]::GetFolderPath('MyDocuments'))\WindowsPowerShell\Modules"
New-Item -ItemType Directory -Force -Path $targetondisk | out-null
$shell_app=new-object -com shell.application
$zip_file = $shell_app.namespace($file)
Write-Host "Uncompressing the Zip file to $($targetondisk)" -ForegroundColor Cyan
$destination = $shell_app.namespace($targetondisk)
$destination.Copyhere($zip_file.items(), 0x10)
# Rename and import
Write-Host "Renaming folder" -ForegroundColor Cyan
Rename-Item -Path ($targetondisk+"\PowerSploit-master") -NewName "PowerSploit" -Force
Write-Host "Module has been installed" -ForegroundColor Green
Import-Module -Name PowerSploit
Get-Command -Module PowerSploit
