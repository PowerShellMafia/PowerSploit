/*
 * NTFS Attribute Classes
 * 
 * Copyright(C) 2010 cyb70289 <cyb70289@gmail.com>
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

#ifndef	__NTFS_ATTRIBUTE_H_CYB70289
#define	__NTFS_ATTRIBUTE_H_CYB70289


////////////////////////////////
// List to hold parsed DataRuns
////////////////////////////////
typedef struct tagDataRun_Entry
{
	LONGLONG			LCN;		// -1 to indicate sparse data
	ULONGLONG			Clusters;
	ULONGLONG			StartVCN;
	ULONGLONG			LastVCN;
} DataRun_Entry;
typedef class CSList<DataRun_Entry> CDataRunList;

////////////////////////////////////
// List to hold Index Entry objects
////////////////////////////////////
class CIndexEntry;
typedef class CSList<CIndexEntry> CIndexEntryList;


////////////////////////////////
// Attributes base class
////////////////////////////////
class CAttrBase
{
public:
	CAttrBase(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr);
	virtual ~CAttrBase();

protected:
	const ATTR_HEADER_COMMON *AttrHeader;
	WORD _SectorSize;
	DWORD _ClusterSize;
	DWORD _IndexBlockSize;
	HANDLE _hVolume;
	const CFileRecord *FileRecord;

public:
	__inline const ATTR_HEADER_COMMON* GetAttrHeader() const;
	__inline DWORD GetAttrType() const;
	__inline DWORD GetAttrTotalSize() const;
	__inline BOOL IsNonResident() const;
	__inline WORD GetAttrFlags() const;
	int GetAttrName(char *buf, DWORD bufLen) const;
	int GetAttrName(wchar_t *buf, DWORD bufLen) const;
	__inline BOOL IsUnNamed() const;

protected:
	virtual __inline BOOL IsDataRunOK() const = 0;

public:
	virtual __inline ULONGLONG GetDataSize(ULONGLONG *allocSize = NULL) const = 0;
	virtual BOOL ReadData(const ULONGLONG &offset, void *bufv, DWORD bufLen, DWORD *actural) const = 0;
};	// CAttrBase

CAttrBase::CAttrBase(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr)
{
	_ASSERT(ahc);
	_ASSERT(fr);

	AttrHeader = ahc;
	FileRecord = fr;

	_SectorSize = fr->Volume->SectorSize;
	_ClusterSize = fr->Volume->ClusterSize;
	_IndexBlockSize = fr->Volume->IndexBlockSize;
	_hVolume = fr->Volume->hVolume;
}

CAttrBase::~CAttrBase()
{
}

__inline const ATTR_HEADER_COMMON* CAttrBase::GetAttrHeader() const
{
	return AttrHeader;
}

__inline DWORD CAttrBase::GetAttrType() const
{
	return AttrHeader->Type;
}

__inline DWORD CAttrBase::GetAttrTotalSize() const
{
	return AttrHeader->TotalSize;
}

__inline BOOL CAttrBase::IsNonResident() const
{
	return AttrHeader->NonResident;
}

__inline WORD CAttrBase::GetAttrFlags() const
{
	return AttrHeader->Flags;
}

// Get ANSI Attribute name
// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
int CAttrBase::GetAttrName(char *buf, DWORD bufLen) const
{
	if (AttrHeader->NameLength)
	{
		if (bufLen < AttrHeader->NameLength)
			return -1*AttrHeader->NameLength;	// buffer too small

		wchar_t *namePtr = (wchar_t*)((BYTE*)AttrHeader + AttrHeader->NameOffset);
		int len = WideCharToMultiByte(CP_ACP, 0, namePtr, AttrHeader->NameLength,
			buf, bufLen, NULL, NULL);
		if (len)
		{
			buf[len] = '\0';
			NTFS_TRACE1("Attribute name: %s\n", buf);
			return len;
		}
		else
		{
			NTFS_TRACE("Unrecognized attribute name or Name buffer too small\n");
			return -1*AttrHeader->NameLength;
		}
	}
	else
	{
		NTFS_TRACE("Attribute is unnamed\n");
		return 0;
	}
}

// Get UNICODE Attribute name
// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
int CAttrBase::GetAttrName(wchar_t *buf, DWORD bufLen) const
{
	if (AttrHeader->NameLength)
	{
		if (bufLen < AttrHeader->NameLength)
			return -1*AttrHeader->NameLength;	// buffer too small

		bufLen = AttrHeader->NameLength;
		wchar_t *namePtr = (wchar_t*)((BYTE*)AttrHeader + AttrHeader->NameOffset);
		wcsncpy(buf, namePtr, bufLen);
		buf[bufLen] = '\0\0';

		NTFS_TRACE("Unicode Attribute Name\n");
		return bufLen;
	}
	else
	{
		NTFS_TRACE("Attribute is unnamed\n");
		return 0;
	}
}

// Verify if this attribute is unnamed
// Useful in analyzing MultiStream files
__inline BOOL CAttrBase::IsUnNamed() const
{
	return (AttrHeader->NameLength == 0);
}


////////////////////////////////
// Resident Attributes
////////////////////////////////
class CAttrResident : public CAttrBase
{
public:
	CAttrResident(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr);
	virtual ~CAttrResident();

protected:
	const ATTR_HEADER_RESIDENT *AttrHeaderR;
	const void *AttrBody;	// Points to Resident Data
	DWORD AttrBodySize;		// Attribute Data Size

	virtual __inline BOOL IsDataRunOK() const;

public:
	virtual __inline ULONGLONG GetDataSize(ULONGLONG *allocSize = NULL) const;
	virtual BOOL ReadData(const ULONGLONG &offset, void *bufv, DWORD bufLen, DWORD *actural) const;
};	// CAttrResident

CAttrResident::CAttrResident(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : CAttrBase(ahc, fr)
{
	AttrHeaderR = (ATTR_HEADER_RESIDENT*)ahc;
	AttrBody = (void*)((BYTE*)AttrHeaderR + AttrHeaderR->AttrOffset);
	AttrBodySize = AttrHeaderR->AttrSize;
}

CAttrResident::~CAttrResident()
{
}

__inline BOOL CAttrResident::IsDataRunOK() const
{
	return TRUE;	// Always OK for a resident attribute
}

// Return Actural Data Size
// *allocSize = Allocated Size
__inline ULONGLONG CAttrResident::GetDataSize(ULONGLONG *allocSize) const
{
	if (allocSize)
		*allocSize = AttrBodySize;

	return (ULONGLONG)AttrBodySize;
}

// Read "bufLen" bytes from "offset" into "bufv"
// Number of bytes acturally read is returned in "*actural"
BOOL CAttrResident::ReadData(const ULONGLONG &offset, void *bufv, DWORD bufLen, DWORD *actural) const
{
	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	DWORD offsetd = (DWORD)offset;
	if (offsetd >= AttrBodySize)
		return FALSE;	// offset parameter error

	if ((offsetd + bufLen) > AttrBodySize)
		*actural = AttrBodySize - offsetd;	// Beyond scope
	else
		*actural = bufLen;

	memcpy(bufv, (BYTE*)AttrBody + offsetd, *actural);

	return TRUE;
}


////////////////////////////////
// NonResident Attributes
////////////////////////////////
class CAttrNonResident : public CAttrBase
{
public:
	CAttrNonResident(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr);
	virtual ~CAttrNonResident();

protected:
	const ATTR_HEADER_NON_RESIDENT *AttrHeaderNR;
	CDataRunList DataRunList;

private:
	BOOL bDataRunOK;
	BYTE *UnalignedBuf;	// Buffer to hold not cluster aligned data
	BOOL PickData(const BYTE **dataRun, LONGLONG *length, LONGLONG *LCNOffset);
	BOOL ParseDataRun();
	BOOL ReadClusters(void *buf, DWORD clusters, LONGLONG lcn);
	BOOL ReadVirtualClusters(ULONGLONG vcn, DWORD clusters,
		void *bufv, DWORD bufLen, DWORD *actural);

protected:
	virtual __inline BOOL IsDataRunOK() const;

public:
	virtual __inline ULONGLONG GetDataSize(ULONGLONG *allocSize = NULL) const;
	virtual BOOL ReadData(const ULONGLONG &offset, void *bufv, DWORD bufLen, DWORD *actural) const;
};	// CAttrNonResident

CAttrNonResident::CAttrNonResident(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : CAttrBase(ahc, fr)
{
	AttrHeaderNR = (ATTR_HEADER_NON_RESIDENT*)ahc;

	UnalignedBuf = new BYTE[_ClusterSize];

	bDataRunOK = ParseDataRun();
}

CAttrNonResident::~CAttrNonResident()
{
	delete UnalignedBuf;

	DataRunList.RemoveAll();
}

// Parse a single DataRun unit
BOOL CAttrNonResident::PickData(const BYTE **dataRun, LONGLONG *length, LONGLONG *LCNOffset)
{
	BYTE size = **dataRun;
	(*dataRun)++;
	int lengthBytes = size & 0x0F;
	int offsetBytes = size >> 4;

	if (lengthBytes > 8 || offsetBytes > 8)
	{
		NTFS_TRACE1("DataRun decode error 1: 0x%02X\n", size);
		return FALSE;
	}

	*length = 0;
	memcpy(length, *dataRun, lengthBytes);
	if (*length < 0)
	{
		NTFS_TRACE1("DataRun length error: %I64d\n", *length);
		return FALSE;
	}

	(*dataRun) += lengthBytes;
	*LCNOffset = 0;
	if (offsetBytes)	// Not Sparse File
	{
		if ((*dataRun)[offsetBytes-1] & 0x80)
			*LCNOffset = -1;
		memcpy(LCNOffset, *dataRun, offsetBytes);

		(*dataRun) += offsetBytes;
	}

	return TRUE;
}

// Travers DataRun and insert into a link list
BOOL CAttrNonResident::ParseDataRun()
{
	NTFS_TRACE("Parsing Non Resident DataRun\n");
	NTFS_TRACE2("Start VCN = %I64u, End VCN = %I64u\n",
			AttrHeaderNR->StartVCN, AttrHeaderNR->LastVCN);

	const BYTE *dataRun = (BYTE*)AttrHeaderNR + AttrHeaderNR->DataRunOffset;
	LONGLONG length;
	LONGLONG LCNOffset;
	LONGLONG LCN = 0;
	ULONGLONG VCN = 0;

	while (*dataRun)
	{
		if (PickData(&dataRun, &length, &LCNOffset))
		{
			LCN += LCNOffset;
			if (LCN < 0)
			{
				NTFS_TRACE("DataRun decode error 2\n");
				return FALSE;
			}

			NTFS_TRACE2("Data length = %I64d clusters, LCN = %I64d", length, LCN);
			NTFS_TRACE(LCNOffset == 0 ? ", Sparse Data\n" : "\n");

			// Store LCN, Data size (clusters) into list
			DataRun_Entry *dr = new DataRun_Entry;
			dr->LCN = (LCNOffset == 0) ? -1 : LCN;
			dr->Clusters = length;
			dr->StartVCN = VCN;
			VCN += length;
			dr->LastVCN = VCN - 1;

			if (dr->LastVCN <= (AttrHeaderNR->LastVCN - AttrHeaderNR->StartVCN))
			{
				DataRunList.InsertEntry(dr);
			}
			else
			{
				NTFS_TRACE("DataRun decode error: VCN exceeds bound\n");

				// Remove entries
				DataRunList.RemoveAll();

				return FALSE;
			}
		}
		else
			break;
	}

	return TRUE;
}

// Read clusters from disk, or sparse data
// *actural = Clusters acturally read
BOOL CAttrNonResident::ReadClusters(void *buf, DWORD clusters, LONGLONG lcn)
{
	if (lcn == -1)	// sparse data
	{
		NTFS_TRACE("Sparse Data, Fill the buffer with 0\n");

		// Fill the buffer with 0
		memset(buf, 0, clusters * _ClusterSize);

		return TRUE;
	}

	LARGE_INTEGER addr;
	DWORD len;

	addr.QuadPart = lcn * _ClusterSize;
	len = SetFilePointer(_hVolume, addr.LowPart, &addr.HighPart, FILE_BEGIN);

	if (len == (DWORD)-1 && GetLastError() != NO_ERROR)
	{
		NTFS_TRACE1("Cannot locate cluster with LCN %I64d\n", lcn);
	}
	else
	{
		if (ReadFile(_hVolume, buf, clusters*_ClusterSize, &len, NULL) &&
			len == clusters*_ClusterSize)
		{
			NTFS_TRACE2("Successfully read %u clusters from LCN %I64d\n", clusters, lcn);
			return TRUE;
		}
		else
		{
			NTFS_TRACE1("Cannot read cluster with LCN %I64d\n", lcn);
		}
	}

	return FALSE;
}

// Read Data, cluster based
// clusterNo: Begnning cluster Number
// clusters: Clusters to read
// bufv, bufLen: Returned data
// *actural = Number of bytes acturally read
BOOL CAttrNonResident::ReadVirtualClusters(ULONGLONG vcn, DWORD clusters,
	void *bufv, DWORD bufLen, DWORD *actural)
{
	_ASSERT(bufv);
	_ASSERT(clusters);

	*actural = 0;
	BYTE *buf = (BYTE*)bufv;

	// Verify if clusters exceeds DataRun bounds
	if (vcn + clusters > (AttrHeaderNR->LastVCN - AttrHeaderNR->StartVCN +1))
	{
		NTFS_TRACE("Cluster exceeds DataRun bounds\n");
		return FALSE;
	}

	// Verify buffer size
	if (bufLen < clusters*_ClusterSize)
	{
		NTFS_TRACE("Buffer size too small\n");
		return FALSE;
	}

	// Traverse the DataRun List to find the according LCN
	const DataRun_Entry *dr = DataRunList.FindFirstEntry();
	while(dr)
	{
		if (vcn>=dr->StartVCN && vcn<=dr->LastVCN)
		{
			DWORD clustersToRead;

			ULONGLONG vcns = dr->LastVCN - vcn + 1;	// Clusters from read pointer to the end

			if ((ULONGLONG)clusters > vcns)	// Fragmented data, we must go on
				clustersToRead = (DWORD)vcns;
			else
				clustersToRead = clusters;
			if (ReadClusters(buf, clustersToRead, dr->LCN+(vcn-dr->StartVCN)))
			{
				buf += clustersToRead*_ClusterSize;
				clusters -= clustersToRead;
				*actural += clustersToRead;
				vcn += clustersToRead;
			}
			else
				break;

			if (clusters == 0)
				break;
		}

		dr = DataRunList.FindNextEntry();
	}

	*actural *= _ClusterSize;
	return TRUE;
}

// Judge if the DataRun is successfully parsed
__inline BOOL CAttrNonResident::IsDataRunOK() const
{
	return bDataRunOK;
}

// Return Actural Data Size
// *allocSize = Allocated Size
__inline ULONGLONG CAttrNonResident::GetDataSize(ULONGLONG *allocSize) const
{
	if (allocSize)
		*allocSize = AttrHeaderNR->AllocSize;

	return AttrHeaderNR->RealSize;
}

// Read "bufLen" bytes from "offset" into "bufv"
// Number of bytes acturally read is returned in "*actural"
BOOL CAttrNonResident::ReadData(const ULONGLONG &offset, void *bufv, DWORD bufLen, DWORD *actural) const
{
	// Hard disks can only be accessed by sectors
	// To be simple and efficient, only implemented cluster based accessing
	// So cluster unaligned data address should be processed carefully here

	_ASSERT(bufv);

	*actural = 0;
	if (bufLen == 0)
		return TRUE;

	// Bounds check
	if (offset > AttrHeaderNR->RealSize)
		return FALSE;
	if ((offset + bufLen) > AttrHeaderNR->RealSize)
		bufLen = (DWORD)(AttrHeaderNR->RealSize - offset);

	DWORD len;
	BYTE *buf = (BYTE*)bufv;

	// First cluster Number
	ULONGLONG startVCN = offset / _ClusterSize;
	// Bytes in first cluster
	DWORD startBytes = _ClusterSize - (DWORD)(offset % _ClusterSize);
	// Read first cluster
	if (startBytes != _ClusterSize)
	{
		// First cluster, Unaligned
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
			&& len == _ClusterSize)
		{
			len = (startBytes < bufLen) ? startBytes : bufLen;
			memcpy(buf, UnalignedBuf + _ClusterSize - startBytes, len);
			buf += len;
			bufLen -= len;
			*actural += len;
			startVCN++;
		}
		else
			return FALSE;
	}
	if (bufLen == 0)
		return TRUE;

	DWORD alignedClusters = bufLen / _ClusterSize;
	if (alignedClusters)
	{
		// Aligned clusters
		DWORD alignedSize = alignedClusters*_ClusterSize;
		if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, alignedClusters, buf, alignedSize, &len)
			&& len == alignedSize)
		{
			startVCN += alignedClusters;
			buf += alignedSize;
			bufLen %= _ClusterSize;
			*actural += len;

			if (bufLen == 0)
				return TRUE;
		}
		else
			return FALSE;
	}

	// Last cluster, Unaligned
	if (((CAttrNonResident*)this)->ReadVirtualClusters(startVCN, 1, UnalignedBuf, _ClusterSize, &len)
		&& len == _ClusterSize)
	{
		memcpy(buf, UnalignedBuf, bufLen);
		*actural += bufLen;

		return TRUE;
	}
	else
		return FALSE;
}


///////////////////////////////////
// Attribute: Standard Information
///////////////////////////////////
class CAttr_StdInfo : public CAttrResident
{
public:
	CAttr_StdInfo(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr);
	virtual ~CAttr_StdInfo();

private:
	const ATTR_STANDARD_INFORMATION *StdInfo;

public:
	void GetFileTime(FILETIME *writeTm, FILETIME *createTm = NULL, FILETIME *accessTm = NULL) const;
	__inline DWORD GetFilePermission() const;
	__inline BOOL IsReadOnly() const;
	__inline BOOL IsHidden() const;
	__inline BOOL IsSystem() const;
	__inline BOOL IsCompressed() const;
	__inline BOOL IsEncrypted() const;
	__inline BOOL IsSparse() const;

	static void UTC2Local(const ULONGLONG &ultm, FILETIME *lftm);
};	// CAttr_StdInfo

CAttr_StdInfo::CAttr_StdInfo(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : CAttrResident(ahc, fr)
{
	NTFS_TRACE("Attribute: Standard Information\n");

	StdInfo = (ATTR_STANDARD_INFORMATION*)AttrBody;
}

CAttr_StdInfo::~CAttr_StdInfo()
{
	NTFS_TRACE("CAttr_StdInfo deleted\n");
}

// Change from UTC time to local time
void CAttr_StdInfo::GetFileTime(FILETIME *writeTm, FILETIME *createTm, FILETIME *accessTm) const
{
	UTC2Local(StdInfo->AlterTime, writeTm);

	if (createTm)
		UTC2Local(StdInfo->CreateTime, createTm);

	if (accessTm)
		UTC2Local(StdInfo->ReadTime, accessTm);
}

__inline DWORD CAttr_StdInfo::GetFilePermission() const
{
	return StdInfo->Permission;
}

__inline BOOL CAttr_StdInfo::IsReadOnly() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_READONLY);
}

__inline BOOL CAttr_StdInfo::IsHidden() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_HIDDEN);
}

__inline BOOL CAttr_StdInfo::IsSystem() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_SYSTEM);
}

__inline BOOL CAttr_StdInfo::IsCompressed() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_COMPRESSED);
}

__inline BOOL CAttr_StdInfo::IsEncrypted() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_ENCRYPTED);
}

__inline BOOL CAttr_StdInfo::IsSparse() const
{
	return ((StdInfo->Permission) & ATTR_STDINFO_PERMISSION_SPARSE);
}

// UTC filetime to Local filetime
void CAttr_StdInfo::UTC2Local(const ULONGLONG &ultm, FILETIME *lftm)
{
	LARGE_INTEGER fti;
	FILETIME ftt;

	fti.QuadPart = ultm;
	ftt.dwHighDateTime = fti.HighPart;
	ftt.dwLowDateTime = fti.LowPart;

	if (!FileTimeToLocalFileTime(&ftt, lftm))
		*lftm = ftt;
}


////////////////////////////////////////
// FileName helper class
// used by FileName and IndexEntry
////////////////////////////////////////
class CFileName
{
public:
	CFileName(ATTR_FILE_NAME *fn = NULL);
	virtual ~CFileName();

protected:
	const ATTR_FILE_NAME *FileName;	// May be NULL for an IndexEntry
	wchar_t *FileNameWUC;	// Uppercase Unicode File Name, used to compare file names
	int FileNameLength;
	BOOL IsCopy;

	__inline void SetFileName(ATTR_FILE_NAME *fn);
	void CFileName::CopyFileName(const CFileName *fn, const ATTR_FILE_NAME *afn);

private:
	void GetFileNameWUC();

public:
	int Compare(const wchar_t *fn) const;
	int Compare(const char *fn) const;

	__inline ULONGLONG GetFileSize() const;
	__inline DWORD GetFilePermission() const;
	__inline BOOL IsReadOnly() const;
	__inline BOOL IsHidden() const;
	__inline BOOL IsSystem() const;
	__inline BOOL IsDirectory() const;
	__inline BOOL IsCompressed() const;
	__inline BOOL IsEncrypted() const;
	__inline BOOL IsSparse() const;

	int GetFileName(char *buf, DWORD bufLen) const;
	int GetFileName(wchar_t *buf, DWORD bufLen) const;
	__inline BOOL HasName() const;
	__inline BOOL IsWin32Name() const;

	void GetFileTime(FILETIME *writeTm, FILETIME *createTm = NULL, FILETIME *accessTm = NULL) const;
};	// CFileName

CFileName::CFileName(ATTR_FILE_NAME *fn)
{
	IsCopy = FALSE;

	FileName = fn;

	FileNameWUC = NULL;
	FileNameLength = 0;

	if (fn)
		GetFileNameWUC();
}

CFileName::~CFileName()
{
	if (FileNameWUC)
		delete FileNameWUC;
}

__inline void CFileName::SetFileName(ATTR_FILE_NAME *fn)
{
	FileName = fn;

	GetFileNameWUC();
}

// Copy pointer buffers
void CFileName::CopyFileName(const CFileName *fn, const ATTR_FILE_NAME *afn)
{
	if (!IsCopy)
	{
		NTFS_TRACE("Cannot call this routine\n");
		return;
	}

	_ASSERT(fn && afn);

	NTFS_TRACE("FileName Copied\n");

	if (FileNameWUC)
		delete FileNameWUC;

	FileNameLength = fn->FileNameLength;
	FileName = afn;

	if (fn->FileNameWUC)
	{
		FileNameWUC = new wchar_t[FileNameLength+1];
		wcsncpy(FileNameWUC, fn->FileNameWUC, FileNameLength);
		FileNameWUC[FileNameLength] = wchar_t('\0');
	}
	else
		FileNameWUC = NULL;
}

// Get uppercase unicode filename and store it in a buffer
void CFileName::GetFileNameWUC()
{
#ifdef	_DEBUG
	char fna[MAX_PATH];
	GetFileName(fna, MAX_PATH);	// Just show filename in debug window
#endif

	if (FileNameWUC)
	{
		delete FileNameWUC;
		FileNameWUC = NULL;
		FileNameLength = 0;
	}

	wchar_t fns[MAX_PATH];
	FileNameLength = GetFileName(fns, MAX_PATH);

	if (FileNameLength > 0)
	{
		FileNameWUC = new wchar_t[FileNameLength+1];
		for (int i=0; i<FileNameLength; i++)
			FileNameWUC[i] = towupper(fns[i]);
		FileNameWUC[FileNameLength] = wchar_t('\0');
	}
	else
	{
		FileNameLength = 0;
		FileNameWUC = NULL;
	}
}

// Compare Unicode file name
int CFileName::Compare(const wchar_t *fn) const
{
	// Change fn to upper case
	int len = wcslen(fn);
	if (len > MAX_PATH)
		return 1;	// Assume bigger

	wchar_t fns[MAX_PATH];

	for (int i=0; i<len; i++)
		fns[i] = towupper(fn[i]);
	fns[len] = wchar_t('\0');

	return wcscmp(fns, FileNameWUC);
}

// Compare ANSI file name
int CFileName::Compare(const char *fn) const
{
	wchar_t fnw[MAX_PATH];

	int len = MultiByteToWideChar(CP_ACP, 0, fn, -1, fnw, MAX_PATH);
	if (len)
		return Compare(fnw);
	else
		return 1;	// Assume bigger
}

__inline ULONGLONG CFileName::GetFileSize() const
{
	return FileName ? FileName->RealSize : 0;
}

__inline DWORD CFileName::GetFilePermission() const
{
	return FileName ? FileName->Flags : 0;
}

__inline BOOL CFileName::IsReadOnly() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_READONLY) : FALSE;
}

__inline BOOL CFileName::IsHidden() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_HIDDEN) : FALSE;
}

__inline BOOL CFileName::IsSystem() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_SYSTEM) : FALSE;
}

__inline BOOL CFileName::IsDirectory() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_DIRECTORY) : FALSE;
}

__inline BOOL CFileName::IsCompressed() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_COMPRESSED) : FALSE;
}

__inline BOOL CFileName::IsEncrypted() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_ENCRYPTED) : FALSE;
}

__inline BOOL CFileName::IsSparse() const
{
	return FileName ? ((FileName->Flags) & ATTR_FILENAME_FLAG_SPARSE) : FALSE;
}

// Get ANSI File Name
// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
int CFileName::GetFileName(char *buf, DWORD bufLen) const
{
	if (FileName == NULL)
		return 0;

	int len = 0;

	if (FileName->NameLength)
	{
		if (bufLen < FileName->NameLength)
			return -1*FileName->NameLength;	// buffer too small

		len = WideCharToMultiByte(CP_ACP, 0, (wchar_t*)FileName->Name, FileName->NameLength,
				buf, bufLen, NULL, NULL);
		if (len)
		{
			buf[len] = '\0';
			NTFS_TRACE1("File Name: %s\n", buf);
			NTFS_TRACE4("File Permission: %s\t%c%c%c\n", IsDirectory()?"Directory":"File",
				IsReadOnly()?'R':' ', IsHidden()?'H':' ', IsSystem()?'S':' ');
		}
		else
		{
			NTFS_TRACE("Unrecognized File Name or FileName buffer too small\n");
		}
	}

	return len;
}

// Get Unicode File Name
// Return 0: Unnamed, <0: buffer too small, -buffersize, >0 Name length
int CFileName::GetFileName(wchar_t *buf, DWORD bufLen) const
{
	if (FileName == NULL)
		return 0;

	if (FileName->NameLength)
	{
		if (bufLen < FileName->NameLength)
			return -1*FileName->NameLength;	// buffer too small

		bufLen = FileName->NameLength;
		wcsncpy(buf, (wchar_t*)FileName->Name, bufLen);
		buf[bufLen] = wchar_t('\0');

		return bufLen;
	}

	return 0;
}

__inline BOOL CFileName::HasName() const
{
	return FileNameLength > 0;
}

__inline BOOL CFileName::IsWin32Name() const
{
	if (FileName == NULL || FileNameLength <= 0)
		return FALSE;

	return (FileName->NameSpace != ATTR_FILENAME_NAMESPACE_DOS);	// POSIX, WIN32, WIN32_DOS
}

// Change from UTC time to local time
void CFileName::GetFileTime(FILETIME *writeTm, FILETIME *createTm, FILETIME *accessTm) const
{
	CAttr_StdInfo::UTC2Local(FileName ? FileName->AlterTime : 0, writeTm);

	if (createTm)
		CAttr_StdInfo::UTC2Local(FileName ? FileName->CreateTime : 0, createTm);

	if (accessTm)
		CAttr_StdInfo::UTC2Local(FileName ? FileName->ReadTime : 0, accessTm);
}


////////////////////////////////
// Attribute: File Name
////////////////////////////////
class CAttr_FileName : public CAttrResident, public CFileName
{
public:
	CAttr_FileName(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : CAttrResident(ahc, fr)
	{
		NTFS_TRACE("Attribute: File Name\n");

		SetFileName((ATTR_FILE_NAME*)AttrBody);
	}

	virtual ~CAttr_FileName()
	{
		NTFS_TRACE("CAttr_FileName deleted\n");
	}

private:
	// File permission and time in $FILE_NAME only updates when the filename changes
	// So hide these functions to prevent user from getting the error information
	// Standard Information and IndexEntry keeps the most recent file time and permission infomation
	void GetFileTime(FILETIME *writeTm, FILETIME *createTm = NULL, FILETIME *accessTm = NULL) const {}
	__inline DWORD GetFilePermission(){}
	__inline BOOL IsReadOnly() const {}
	__inline BOOL IsHidden() const {}
	__inline BOOL IsSystem() const {}
	__inline BOOL IsCompressed() const {}
	__inline BOOL IsEncrypted() const {}
	__inline BOOL IsSparse() const {}
};	// CAttr_FileName


//////////////////////////////////
// Attribute: Volume Information
//////////////////////////////////
class CAttr_VolInfo : public CAttrResident
{
public:
	CAttr_VolInfo(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : CAttrResident(ahc, fr)
	{
		NTFS_TRACE("Attribute: Volume Information\n");

		VolInfo = (ATTR_VOLUME_INFORMATION*)AttrBody;
	}

	virtual ~CAttr_VolInfo()
	{
		NTFS_TRACE("CAttr_VolInfo deleted\n");
	}

private:
	const ATTR_VOLUME_INFORMATION *VolInfo;

public:
	// Get NTFS Volume Version
	__inline WORD GetVersion()
	{
		return MAKEWORD(VolInfo->MinorVersion, VolInfo->MajorVersion);
	}
}; // CAttr_VolInfo


///////////////////////////
// Attribute: Volume Name
///////////////////////////
class CAttr_VolName : public CAttrResident
{
public:
	CAttr_VolName(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : CAttrResident(ahc, fr)
	{
		NTFS_TRACE("Attribute: Volume Name\n");

		NameLength = AttrBodySize >> 1;
		VolNameU = new wchar_t[NameLength+1];
		VolNameA = new char[NameLength+1];

		memcpy(VolNameU, AttrBody, AttrBodySize);
		VolNameU[NameLength] = wchar_t('\0');

		int len = WideCharToMultiByte(CP_ACP, 0, VolNameU, NameLength,
			VolNameA, NameLength, NULL, NULL);
		VolNameA[NameLength] = '\0';
	}

	virtual ~CAttr_VolName()
	{
		NTFS_TRACE("CAttr_VolName deleted\n");

		delete VolNameU;
		delete VolNameA;
	}

private:
	wchar_t *VolNameU;
	char *VolNameA;
	DWORD NameLength;

public:
	// Get NTFS Volume Unicode Name
	__inline int GetName(wchar_t *buf, DWORD len) const
	{
		if (len < NameLength)
			return -1*NameLength;	// buffer too small

		wcsncpy(buf, VolNameU, NameLength+1);
		return NameLength;
	}

	// ANSI Name
	__inline int GetName(char *buf, DWORD len) const
	{
		if (len < NameLength)
			return -1*NameLength;	// buffer too small

		strncpy(buf, VolNameA, NameLength+1);
		return NameLength;
	}
}; // CAttr_VolInfo


/////////////////////////////////////
// Attribute: Data
/////////////////////////////////////
template <class TYPE_RESIDENT>
class CAttr_Data : public TYPE_RESIDENT
{
public:
	CAttr_Data(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : TYPE_RESIDENT(ahc, fr)
	{
		NTFS_TRACE1("Attribute: Data (%sResident)\n", IsNonResident() ? "Non" : "");
	}

	virtual ~CAttr_Data()
	{
		NTFS_TRACE("CAttr_Data deleted\n");
	}
};	// CAttr_Data


/////////////////////////////
// Index Entry helper class
/////////////////////////////
class CIndexEntry : public CFileName
{
public:
	CIndexEntry()
	{
		NTFS_TRACE("Index Entry\n");

		IsDefault = TRUE;

		IndexEntry = NULL;
		SetFileName(NULL);
	}

	CIndexEntry(const INDEX_ENTRY *ie)
	{
		NTFS_TRACE("Index Entry\n");

		IsDefault = FALSE;

		_ASSERT(ie);
		IndexEntry = ie;

		if (IsSubNodePtr())
		{
			NTFS_TRACE("Points to sub-node\n");
		}

		if (ie->StreamSize)
		{
			SetFileName((ATTR_FILE_NAME*)(ie->Stream));
		}
		else
		{
			NTFS_TRACE("No FileName stream found\n");
		}
	}

	virtual ~CIndexEntry()
	{
		// Never touch *IndexEntry here if IsCopy == FALSE !
		// As the memory have been deallocated by ~CIndexBlock()

		if (IsCopy && IndexEntry)
			delete (void*)IndexEntry;

		NTFS_TRACE("CIndexEntry deleted\n");
	}

private:
	BOOL IsDefault;

protected:
	const INDEX_ENTRY *IndexEntry;

public:
	// Use with caution !
	CIndexEntry& operator = (const CIndexEntry &ieClass)
	{
		if (!IsDefault)
		{
			NTFS_TRACE("Cannot call this routine\n");
			return *this;
		}

		NTFS_TRACE("Index Entry Copied\n");

		IsCopy = TRUE;

		if (IndexEntry)
		{
			delete (void*)IndexEntry;
			IndexEntry = NULL;
		}

		const INDEX_ENTRY *ie = ieClass.IndexEntry;
		_ASSERT(ie && (ie->Size > 0));

		IndexEntry = (INDEX_ENTRY*)new BYTE[ie->Size];
		memcpy((void*)IndexEntry, ie, ie->Size);
		CopyFileName(&ieClass, (ATTR_FILE_NAME*)(IndexEntry->Stream));

		return *this;
	}

	__inline ULONGLONG GetFileReference() const
	{
		if (IndexEntry)
			return IndexEntry->FileReference & 0x0000FFFFFFFFFFFFUL;
		else
			return (ULONGLONG)-1;
	}

	__inline BOOL IsSubNodePtr() const
	{
		if (IndexEntry)
			return (IndexEntry->Flags & INDEX_ENTRY_FLAG_SUBNODE);
		else
			return FALSE;
	}

	__inline ULONGLONG GetSubNodeVCN() const
	{
		if (IndexEntry)
			return *(ULONGLONG*)((BYTE*)IndexEntry + IndexEntry->Size - 8);
		else
			return (ULONGLONG)-1;
	}
};	// CIndexEntry


///////////////////////////////
// Index Block helper class
///////////////////////////////
class CIndexBlock : public CIndexEntryList
{
public:
	CIndexBlock()
	{
		NTFS_TRACE("Index Block\n");

		IndexBlock = NULL;
	}

	virtual ~CIndexBlock()
	{
		NTFS_TRACE("IndexBlock deleted\n");

		if (IndexBlock)
			delete IndexBlock;
	}

private:
	INDEX_BLOCK *IndexBlock;

public:
	INDEX_BLOCK *AllocIndexBlock(DWORD size)
	{
		// Free previous data if any
		if (GetCount() > 0)
			RemoveAll();
		if (IndexBlock)
			delete IndexBlock;

		IndexBlock = (INDEX_BLOCK*)new BYTE[size];

		return IndexBlock;
	}
};	// CIndexBlock


/////////////////////////////////////
// Attribute: Index Root (Resident)
/////////////////////////////////////
class CAttr_IndexRoot : public CAttrResident, public CIndexEntryList
{
public:
	CAttr_IndexRoot(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr);
	virtual ~CAttr_IndexRoot();

private:
	const ATTR_INDEX_ROOT *IndexRoot;

	void ParseIndexEntries();

public:
	__inline BOOL IsFileName() const;
};	// CAttr_IndexRoot

CAttr_IndexRoot::CAttr_IndexRoot(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr): CAttrResident(ahc, fr)
{
	NTFS_TRACE("Attribute: Index Root\n");

	IndexRoot = (ATTR_INDEX_ROOT*)AttrBody;

	if (IsFileName())
	{
		ParseIndexEntries();
	}
	else
	{
		NTFS_TRACE("Index View not supported\n");
	}
}

CAttr_IndexRoot::~CAttr_IndexRoot()
{
	NTFS_TRACE("CAttr_IndexRoot deleted\n");
}

// Get all the index entries
void CAttr_IndexRoot::ParseIndexEntries()
{
	INDEX_ENTRY *ie;
	ie = (INDEX_ENTRY*)((BYTE*)(&(IndexRoot->EntryOffset)) + IndexRoot->EntryOffset);

	DWORD ieTotal = ie->Size;

	while (ieTotal <= IndexRoot->TotalEntrySize)
	{
		CIndexEntry *ieClass = new CIndexEntry(ie);
		InsertEntry(ieClass);

		if (ie->Flags & INDEX_ENTRY_FLAG_LAST)
		{
			NTFS_TRACE("Last Index Entry\n");
			break;
		}

		ie = (INDEX_ENTRY*)((BYTE*)ie + ie->Size);	// Pick next
		ieTotal += ie->Size;
	}
}

// Check if this IndexRoot contains FileName or IndexView
__inline BOOL CAttr_IndexRoot::IsFileName() const
{
	return (IndexRoot->AttrType == ATTR_TYPE_FILE_NAME);
}


/////////////////////////////////////////////
// Attribute: Index Allocation (NonResident)
/////////////////////////////////////////////
class CAttr_IndexAlloc : public CAttrNonResident
{
public:
	CAttr_IndexAlloc(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr);
	virtual ~CAttr_IndexAlloc();

private:
	ULONGLONG IndexBlockCount;

	BOOL PatchUS(WORD *sector, int sectors, WORD usn, WORD *usarray);

public:
	__inline ULONGLONG GetIndexBlockCount();
	BOOL ParseIndexBlock(const ULONGLONG &vcn, CIndexBlock &ibClass);
};	// CAttr_IndexAlloc

CAttr_IndexAlloc::CAttr_IndexAlloc(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : CAttrNonResident(ahc, fr)
{
	NTFS_TRACE("Attribute: Index Allocation\n");

	IndexBlockCount = 0;

	if (IsDataRunOK())
	{
		// Get total number of Index Blocks
		ULONGLONG ibTotalSize;
		ibTotalSize = GetDataSize();
		if (ibTotalSize % _IndexBlockSize)
		{
			NTFS_TRACE2("Cannot calulate number of IndexBlocks, total size = %I64u, unit = %u\n",
					ibTotalSize, _IndexBlockSize);
			return;
		}
		IndexBlockCount = ibTotalSize / _IndexBlockSize;
	}
	else
	{
		NTFS_TRACE("Index Allocation DataRun parse error\n");
	}
}

CAttr_IndexAlloc::~CAttr_IndexAlloc()
{
	NTFS_TRACE("CAttr_IndexAlloc deleted\n");
}

// Verify US and update sectors
BOOL CAttr_IndexAlloc::PatchUS(WORD *sector, int sectors, WORD usn, WORD *usarray)
{
	int i;

	for (i=0; i<sectors; i++)
	{
		sector += ((_SectorSize>>1) - 1);
		if (*sector != usn)
			return FALSE;		// USN error
		*sector = usarray[i];	// Write back correct data
		sector++;
	}
	return TRUE;
}

__inline ULONGLONG CAttr_IndexAlloc::GetIndexBlockCount()
{
	return IndexBlockCount;
}

// Parse a single Index Block
// vcn = Index Block VCN in Index Allocation Data Attributes
// ibClass holds the parsed Index Entries
BOOL CAttr_IndexAlloc::ParseIndexBlock(const ULONGLONG &vcn, CIndexBlock &ibClass)
{
	if (vcn >= IndexBlockCount)	// Bounds check
		return FALSE;

	// Allocate buffer for a single Index Block
	INDEX_BLOCK *ibBuf = ibClass.AllocIndexBlock(_IndexBlockSize);

	// Sectors Per Index Block
	DWORD sectors = _IndexBlockSize / _SectorSize;

	// Read one Index Block
	DWORD len;
	if (ReadData(vcn*_IndexBlockSize, ibBuf, _IndexBlockSize, &len) &&
		len == _IndexBlockSize)
	{
		if (ibBuf->Magic != INDEX_BLOCK_MAGIC)
		{
			NTFS_TRACE("Index Block parse error: Magic mismatch\n");
			return FALSE;
		}

		// Patch US
		WORD *usnaddr = (WORD*)((BYTE*)ibBuf + ibBuf->OffsetOfUS);
		WORD usn = *usnaddr;
		WORD *usarray = usnaddr + 1;
		if (!PatchUS((WORD*)ibBuf, sectors, usn, usarray))
		{
			NTFS_TRACE("Index Block parse error: Update Sequence Number\n");
			return FALSE;
		}

		INDEX_ENTRY *ie;
		ie = (INDEX_ENTRY*)((BYTE*)(&(ibBuf->EntryOffset)) + ibBuf->EntryOffset);

		DWORD ieTotal = ie->Size;

		while (ieTotal <= ibBuf->TotalEntrySize)
		{
			CIndexEntry *ieClass = new CIndexEntry(ie);
			ibClass.InsertEntry(ieClass);

			if (ie->Flags & INDEX_ENTRY_FLAG_LAST)
			{
				NTFS_TRACE("Last Index Entry\n");
				break;
			}

			ie = (INDEX_ENTRY*)((BYTE*)ie + ie->Size);	// Pick next
			ieTotal += ie->Size;
		}

		return TRUE;
	}
	else
		return FALSE;
}


////////////////////////////////////////////
// Attribute: Bitmap
////////////////////////////////////////////
template <class TYPE_RESIDENT>
class CAttr_Bitmap : public TYPE_RESIDENT
{
public:
	CAttr_Bitmap(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr);
	virtual ~CAttr_Bitmap();

private:
	ULONGLONG BitmapSize;	// Bitmap data size
	BYTE *BitmapBuf;		// Bitmap data buffer
	LONGLONG CurrentCluster;

public:
	BOOL IsClusterFree(const ULONGLONG &cluster) const;
};	// CAttr_Bitmap

template <class TYPE_RESIDENT>
CAttr_Bitmap<TYPE_RESIDENT>::CAttr_Bitmap(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : TYPE_RESIDENT(ahc, fr)
{
	NTFS_TRACE1("Attribute: Bitmap (%sResident)\n", IsNonResident() ? "Non" : "");

	CurrentCluster = -1;

	if (IsDataRunOK())
	{
		BitmapSize = GetDataSize();

		if (IsNonResident())
			BitmapBuf = new BYTE[_ClusterSize];
		else
		{
			BitmapBuf = new BYTE[(DWORD)BitmapSize];

			DWORD len;
			if (!(ReadData(0, BitmapBuf, (DWORD)BitmapSize, &len)
				&& len == (DWORD)BitmapSize))
			{
				BitmapBuf = NULL;
				NTFS_TRACE("Read Resident Bitmap data failed\n");
			}
			else
			{
				NTFS_TRACE1("%u bytes of resident Bitmap data read\n", len);
			}
		}
	}
	else
	{
		BitmapSize = 0;
		BitmapBuf = 0;
	}
}

template <class TYPE_RESIDENT>
CAttr_Bitmap<TYPE_RESIDENT>::~CAttr_Bitmap()
{
	if (BitmapBuf)
		delete BitmapBuf;

	NTFS_TRACE("CAttr_Bitmap deleted\n");
}

// Verify if a single cluster is free
template <class TYPE_RESIDENT>
BOOL CAttr_Bitmap<TYPE_RESIDENT>::IsClusterFree(const ULONGLONG &cluster) const
{
	if (!IsDataRunOK() || !BitmapBuf)
		return FALSE;

	if (IsNonResident())
	{
		LONGLONG idx = (LONGLONG)cluster >> 3;
		DWORD clusterSize = ((CNTFSVolume*)Volume)->GetClusterSize();

		LONGLONG clusterOffset = idx/clusterSize;
		cluster -= (clusterOffset*clusterSize*8);

		// Read one cluster of data if buffer mismatch
		if (CurrentCluster != clusterOffset)
		{
			DWORD len;
			if (ReadData(clusterOffset, BitmapBuf, clusterSize, &len) && len == clusterSize)
			{
				CurrentCluster = clusterOffset;
			}
			else
			{
				CurrentCluster = -1;
				return FALSE;
			}
		}
	}

	// All the Bitmap data is already in BitmapBuf
	DWORD idx = (DWORD)(cluster >> 3);
	if (IsNonResident() == FALSE)
	{
		if (idx >= BitmapSize)
			return TRUE;	// Resident data bounds check error
	}

	BYTE fac = (BYTE)(cluster % 8);

	return ((BitmapBuf[idx] & (1<<fac)) == 0);
}


////////////////////////////////////////////
// List to hold external File Records
////////////////////////////////////////////
typedef CSList<CFileRecord> CFileRecordList;

////////////////////////////////////////////
// Attribute: Attribute List
////////////////////////////////////////////
template <class TYPE_RESIDENT>
class CAttr_AttrList : public TYPE_RESIDENT
{
public:
	CAttr_AttrList(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr);
	virtual ~CAttr_AttrList();

private:
	CFileRecordList FileRecordList;
};	// CAttr_AttrList

template <class TYPE_RESIDENT>
CAttr_AttrList<TYPE_RESIDENT>::CAttr_AttrList(const ATTR_HEADER_COMMON *ahc, const CFileRecord *fr) : TYPE_RESIDENT(ahc, fr)
{
	NTFS_TRACE("Attribute: Attribute List\n");
	if (fr->FileReference == (ULONGLONG)-1)
		return;

	ULONGLONG offset = 0;
	DWORD len;
	ATTR_ATTRIBUTE_LIST alRecord;

	while (ReadData(offset, &alRecord, sizeof(ATTR_ATTRIBUTE_LIST), &len) &&
		len == sizeof(ATTR_ATTRIBUTE_LIST))
	{
		if (ATTR_INDEX(alRecord.AttrType) > ATTR_NUMS)
		{
			NTFS_TRACE("Attribute List parse error1\n");
			break;
		}

		NTFS_TRACE1("Attribute List: 0x%04x\n", alRecord.AttrType);

		ULONGLONG recordRef = alRecord.BaseRef & 0x0000FFFFFFFFFFFFUL;
		if (recordRef != fr->FileReference)	// Skip contained attributes
		{
			DWORD am = ATTR_MASK(alRecord.AttrType);
			if (am & fr->AttrMask)	// Skip unwanted attributes
			{
				CFileRecord *frnew = new CFileRecord(fr->Volume);
				FileRecordList.InsertEntry(frnew);

				frnew->AttrMask = am;
				if (!frnew->ParseFileRecord(recordRef))
				{
					NTFS_TRACE("Attribute List parse error2\n");
					break;
				}
				frnew->ParseAttrs();

				// Insert new found AttrList to fr->AttrList
				const CAttrBase *ab = (CAttrBase*)frnew->FindFirstAttr(alRecord.AttrType);
				while (ab)
				{
					CAttrList *al = (CAttrList*)&fr->AttrList[ATTR_INDEX(alRecord.AttrType)];
					al->InsertEntry((CAttrBase*)ab);
					ab = frnew->FindNextAttr(alRecord.AttrType);
				}

				// Throw away frnew->AttrList entries to prevent free twice (fr will delete them)
				frnew->AttrList[ATTR_INDEX(alRecord.AttrType)].ThrowAll();
			}
		}

		offset += alRecord.RecordSize;
	}
}

template <class TYPE_RESIDENT>
CAttr_AttrList<TYPE_RESIDENT>::~CAttr_AttrList()
{
	NTFS_TRACE("CAttr_AttrList deleted\n");
}

#endif
