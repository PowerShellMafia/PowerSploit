# ConvertFrom-UACValue

## SYNOPSIS
Converts a UAC int value to human readable form.

Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None

## SYNTAX

```
ConvertFrom-UACValue [-Value] <Int32> [-ShowAll]
```

## DESCRIPTION
This function will take an integer that represents a User Account
Control (UAC) binary blob and will covert it to an ordered
dictionary with each bitwise value broken out.
By default only values
set are displayed- the -ShowAll switch will display all values with
a + next to the ones set.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
ConvertFrom-UACValue -Value 66176
```

Name                           Value
----                           -----
ENCRYPTED_TEXT_PWD_ALLOWED     128
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

### -------------------------- EXAMPLE 2 --------------------------
```
Get-DomainUser harmj0y | ConvertFrom-UACValue
```

Name                           Value
----                           -----
NORMAL_ACCOUNT                 512
DONT_EXPIRE_PASSWORD           65536

### -------------------------- EXAMPLE 3 --------------------------
```
Get-DomainUser harmj0y | ConvertFrom-UACValue -ShowAll
```

Name                           Value
----                           -----
SCRIPT                         1
ACCOUNTDISABLE                 2
HOMEDIR_REQUIRED               8
LOCKOUT                        16
PASSWD_NOTREQD                 32
PASSWD_CANT_CHANGE             64
ENCRYPTED_TEXT_PWD_ALLOWED     128
TEMP_DUPLICATE_ACCOUNT         256
NORMAL_ACCOUNT                 512+
INTERDOMAIN_TRUST_ACCOUNT      2048
WORKSTATION_TRUST_ACCOUNT      4096
SERVER_TRUST_ACCOUNT           8192
DONT_EXPIRE_PASSWORD           65536+
MNS_LOGON_ACCOUNT              131072
SMARTCARD_REQUIRED             262144
TRUSTED_FOR_DELEGATION         524288
NOT_DELEGATED                  1048576
USE_DES_KEY_ONLY               2097152
DONT_REQ_PREAUTH               4194304
PASSWORD_EXPIRED               8388608
TRUSTED_TO_AUTH_FOR_DELEGATION 16777216
PARTIAL_SECRETS_ACCOUNT        67108864

## PARAMETERS

### -Value
Specifies the integer UAC value to convert.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases: UAC, useraccountcontrol

Required: True
Position: 1
Default value: 0
Accept pipeline input: True (ByPropertyName, ByValue)
Accept wildcard characters: False
```

### -ShowAll
Switch.
Signals ConvertFrom-UACValue to display all UAC values, with a + indicating the value is currently set.

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

## INPUTS

### Int

Accepts an integer representing a UAC binary blob.

## OUTPUTS

### System.Collections.Specialized.OrderedDictionary

An ordered dictionary with the converted UAC fields.

## NOTES

## RELATED LINKS

[https://support.microsoft.com/en-us/kb/305144](https://support.microsoft.com/en-us/kb/305144)

