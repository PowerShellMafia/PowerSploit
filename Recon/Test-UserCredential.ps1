function Test-UserCredential
{
<#
.SYNOPSIS

Tests a local or domain username and password. If invalid, returns that information

PowerSploit Function: Test-UserCredential
Author: Rich Lundeen (@webstersprodigy)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None


.PARAMETER Username

Username

.PARAMETER Password

Password

.PARAMETER LDAP server to check

Specify Domain. If domain joined, default username and password to check belong to a domain

.PARAMETER LocalMachine

Specify a machine account rather than a domain account. If the local computer is not domain joined, the default is a local machine account

.OUTPUTS

Returns a tuple. 0th element is whether login was successful. 1st element contains info that can contain additional reasons i.e. expired account, disabled account, etc.

.EXAMPLE

Test-UserCredential -Username user -Password password

Test-UserCredential -Username "otherdomain\username" -Password password -Domain otherdomain.local

Test-UserCredential -Username Administrator -Password password -Machine mymachine

#>

    [CmdletBinding()] Param(
        [Parameter(Mandatory = $True)]
        [String]
        $Username,

        [String]
        [Parameter(Mandatory = $True)]
        $Password,

        [String]
        $Domain,

        [String]
        $Machine
    )
    
    Set-StrictMode -Version 2.0

    #set default parameters
    if ($Domain -eq "" -and $Machine -eq "")
    {
        
        try
        {
            $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().Name
            Write-Verbose "Domain/LocalMachine not specified. Defaulting $Domain"
        }
        catch 
        {
            $Machine = $env:COMPUTERNAME
            Write-Verbose "Computer does not appear domain joined and no domain was specified. Defaulting to local machine $Machine"
        }

    }
    if ($Domain -ne "" -and $Machine -ne "")
    {
        write-error "Domain and Machine should not both be set"
        return
    }

    if ($Domain -ne "")
    {
        try
        {
            if (!$Domain.StartsWith("LDAP://"))
            {
                $Domain = "LDAP://" + $Domain
            }
            $query = New-Object System.DirectoryServices.DirectoryEntry($Domain, $Username, $Password)
            $_t = $query.InvokeGet("Name")
            
            return ($true, "Correct Password")
        }
        catch 
        {
            return  ($false, $_.Exception.InnerException.Message)
        }
    }
    else
    {
        #It would be nice if there were a more portable better way to check local accounts. This requires .net 3.5
        #also note you could check domain accounts with validatecredentials, but it's not as portable

        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine, $Machine)
        try
        {
            if ($DS.ValidateCredentials($Username, $Password))
            {
                return ($true, "Correct Password")
            }
            return ($false, "Logon Failure: Probably unknown username or password")
        }
        catch
        {
            return ($false, $_.Exception.InnerException.Message)
        }
    }
}