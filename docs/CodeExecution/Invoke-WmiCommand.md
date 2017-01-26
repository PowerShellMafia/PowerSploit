# Invoke-WmiCommand

## SYNOPSIS
Executes a PowerShell ScriptBlock on a target computer using WMI as a
pure C2 channel.

Author: Matthew Graeber  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Invoke-WmiCommand [-Payload] <ScriptBlock> [[-RegistryHive] <String>] [[-RegistryKeyPath] <String>]
 [[-RegistryPayloadValueName] <String>] [[-RegistryResultValueName] <String>] [[-ComputerName] <String[]>]
 [[-Credential] <PSCredential>] [[-Impersonation] <ImpersonationLevel>]
 [[-Authentication] <AuthenticationLevel>] [-EnableAllPrivileges] [[-Authority] <String>]
```

## DESCRIPTION
Invoke-WmiCommand executes a PowerShell ScriptBlock on a target
computer using WMI as a pure C2 channel.
It does this by using the
StdRegProv WMI registry provider methods to store a payload into a
registry value.
The command is then executed on the victim system and
the output is stored in another registry value that is then retrieved
remotely.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Invoke-WmiCommand -Payload { if ($True) { 'Do Evil' } } -Credential 'TargetDomain\TargetUser' -ComputerName '10.10.1.1'
```

### -------------------------- EXAMPLE 2 --------------------------
```
$Hosts = Get-Content hostnames.txt
```

PS C:\\\>$Payload = Get-Content payload.ps1
PS C:\\\>$Credential = Get-Credential 'TargetDomain\TargetUser'
PS C:\\\>$Hosts | Invoke-WmiCommand -Payload $Payload -Credential $Credential

### -------------------------- EXAMPLE 3 --------------------------
```
$Payload = Get-Content payload.ps1
```

PS C:\\\>Invoke-WmiCommand -Payload $Payload -Credential 'TargetDomain\TargetUser' -ComputerName '10.10.1.1', '10.10.1.2'

### -------------------------- EXAMPLE 4 --------------------------
```
Invoke-WmiCommand -Payload { 1+3+2+1+1 } -RegistryHive HKEY_LOCAL_MACHINE -RegistryKeyPath 'SOFTWARE\testkey' -RegistryPayloadValueName 'testvalue' -RegistryResultValueName 'testresult' -ComputerName '10.10.1.1' -Credential 'TargetHost\Administrator' -Verbose
```

## PARAMETERS

### -Payload
Specifies the payload to be executed on the remote system.

```yaml
Type: ScriptBlock
Parameter Sets: (All)
Aliases: 

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -RegistryHive
{{Fill RegistryHive Description}}

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 2
Default value: HKEY_CURRENT_USER
Accept pipeline input: False
Accept wildcard characters: False
```

### -RegistryKeyPath
Specifies the registry key where the payload and payload output will
be stored.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 3
Default value: SOFTWARE\Microsoft\Cryptography\RNG
Accept pipeline input: False
Accept wildcard characters: False
```

### -RegistryPayloadValueName
Specifies the registry value name where the payload will be stored.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 4
Default value: Seed
Accept pipeline input: False
Accept wildcard characters: False
```

### -RegistryResultValueName
Specifies the registry value name where the payload output will be
stored.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 5
Default value: Value
Accept pipeline input: False
Accept wildcard characters: False
```

### -ComputerName
Runs the command on the specified computers.
The default is the local
computer.

Type the NetBIOS name, an IP address, or a fully qualified domain
name of one or more computers.
To specify the local computer, type
the computer name, a dot (.), or "localhost".

This parameter does not rely on Windows PowerShell remoting.
You can
use the ComputerName parameter even if your computer is not
configured to run remote commands.

```yaml
Type: String[]
Parameter Sets: (All)
Aliases: Cn

Required: False
Position: 6
Default value: Localhost
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Credential
Specifies a user account that has permission to perform this action.
The default is the current user.
Type a user name, such as "User01",
"Domain01\User01", or User@Contoso.com.
Or, enter a PSCredential
object, such as an object that is returned by the Get-Credential
cmdlet.
When you type a user name, you will be prompted for a
password.

```yaml
Type: PSCredential
Parameter Sets: (All)
Aliases: 

Required: False
Position: 7
Default value: [Management.Automation.PSCredential]::Empty
Accept pipeline input: False
Accept wildcard characters: False
```

### -Impersonation
Specifies the impersonation level to use.
Valid values are:

0: Default (Reads the local registry for the default impersonation level, which is usually set to "3: Impersonate".)

1: Anonymous (Hides the credentials of the caller.)

2: Identify (Allows objects to query the credentials of the caller.)

3: Impersonate (Allows objects to use the credentials of the caller.)

4: Delegate (Allows objects to permit other objects to use the credentials of the caller.)

```yaml
Type: ImpersonationLevel
Parameter Sets: (All)
Aliases: 
Accepted values: Default, Anonymous, Identify, Impersonate, Delegate

Required: False
Position: 8
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Authentication
Specifies the authentication level to be used with the WMI connection.
Valid values are:

-1: Unchanged

0: Default

1: None (No authentication in performed.)

2: Connect (Authentication is performed only when the client establishes a relationship with the application.)

3: Call (Authentication is performed only at the beginning of each call when the application receives the request.)

4: Packet (Authentication is performed on all the data that is received from the client.)

5: PacketIntegrity (All the data that is transferred between the client  and the application is authenticated and verified.)

6: PacketPrivacy (The properties of the other authentication levels are used, and all the data is encrypted.)

```yaml
Type: AuthenticationLevel
Parameter Sets: (All)
Aliases: 
Accepted values: Default, None, Connect, Call, Packet, PacketIntegrity, PacketPrivacy, Unchanged

Required: False
Position: 9
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -EnableAllPrivileges
Enables all the privileges of the current user before the command
makes the WMI call.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: 

Required: False
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Authority
Specifies the authority to use to authenticate the WMI connection.
You can specify standard NTLM or Kerberos authentication.
To use
NTLM, set the authority setting to ntlmdomain:\<DomainName\>, where
\<DomainName\> identifies a valid NTLM domain name.
To use Kerberos,
specify kerberos:\<DomainName\ServerName\>.
You cannot include the
authority setting when you connect to the local computer.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 10
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

### System.String[]

Accepts one or more host names/IP addresses over the pipeline.

## OUTPUTS

### System.Management.Automation.PSObject

Outputs a custom object consisting of the target computer name and
the output of the command executed.

## NOTES
In order to receive the output from your payload, it must return
actual objects.
For example, Write-Host doesn't return objects
rather, it writes directly to the console.
If you're using
Write-Host in your scripts though, you probably don't deserve to get
the output of your payload back.
:P

## RELATED LINKS

