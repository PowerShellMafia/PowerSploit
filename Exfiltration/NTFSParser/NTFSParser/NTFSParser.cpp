/*
 * 
 * Copyright(C) 2013 Joe Bialek Twitter:@JosephBialek
 *
 * This program/include file is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program/include file is distributed in the hope that it will be
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */
//
// This code uses libraries released under GPLv2(or later) written by cyb70289 <cyb70289@gmail.com>

#include "stdafx.h"
#include "NTFS.h"
#include "NTFS_Attribute.h"
#include "NTFS_Common.h"
#include "NTFS_DataType.h"
#include "NTFS_FileRecord.h"

using namespace std;

typedef DWORD (CDECL *StealthReadFile_Func)(string, BYTE*, DWORD, ULONGLONG, DWORD*, ULONGLONG*);

int _tmain(int argc, _TCHAR* argv[])
{
	HMODULE parserDLLHandle = LoadLibraryA("NTFSParserDLL.dll");
	HANDLE procAddress = GetProcAddress(parserDLLHandle, "StealthReadFile");

	StealthReadFile_Func StealthReadFile = (StealthReadFile_Func)procAddress;

	DWORD buffSize = 1024*1024;
	BYTE* buffer = new BYTE[buffSize];
	DWORD bytesRead = 0;
	ULONGLONG bytesLeft = 0;
	DWORD ret = StealthReadFile("c:\\test\\test.txt", buffer, buffSize, 0, &bytesRead, &bytesLeft);

	cout << "Return value: " << ret << endl;

	ofstream myFile("c:\\test\\test2.txt", ios::out | ios::binary);
    myFile.write((char*)buffer, bytesRead);

	return 0;
}

