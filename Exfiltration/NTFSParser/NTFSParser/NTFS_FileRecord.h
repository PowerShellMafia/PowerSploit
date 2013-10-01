/*
 * NTFS Volume and File Record Class
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

#ifndef	__NTFS_FILERECORD_H_CYB70289
#define	__NTFS_FILERECORD_H_CYB70289


///////////////////////////////////////
// NTFS Volume forward declaration
///////////////////////////////////////
class CNTFSVolume
{
public:
	CNTFSVolume(_TCHAR volume);
	virtual ~CNTFSVolume();

	friend class CFileRecord;
	friend class CAttrBase;

private:
	WORD SectorSize;
	DWORD ClusterSize;
	DWORD FileRecordSize;
	DWORD IndexBlockSize;
	ULONGLONG MFTAddr;
	HANDLE hVolume;
	BOOL VolumeOK;
	ATTR_RAW_CALLBACK AttrRawCallBack[ATTR_NUMS];
	WORD Version;

	// MFT file records ($MFT file itself) may be fragmented
	// Get $MFT Data attribute to translate FileRecord to correct disk offset
	CFileRecord *MFTRecord;		// $MFT File Record
	const CAttrBase *MFTData;	// $MFT Data Attribute

	BOOL OpenVolume(_TCHAR volume);

public:
	__inline BOOL IsVolumeOK() const;
	__inline WORD GetVersion() const;
	__inline ULONGLONG GetRecordsCount() const;

	__inline DWORD GetSectorSize() const;
	__inline DWORD GetClusterSize() const;
	__inline DWORD GetFileRecordSize() const;
	__inline DWORD GetIndexBlockSize() const;
	__inline ULONGLONG GetMFTAddr() const;

	BOOL InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb);
	__inline void ClearAttrRawCB();
};	// CNTFSVolume


////////////////////////////////////////////
// List to hold Attributes of the same type
////////////////////////////////////////////
typedef class CSList<CAttrBase> CAttrList;

// It seems VC6.0 doesn't support template class friends
#if	_MSC_VER <= 1200
class CAttrResident;
class CAttrNonResident;
template <class TYPE_RESIDENT> class CAttr_AttrList;
#endif

////////////////////////////////
// Process a single File Record
////////////////////////////////
class CFileRecord
{
public:
	CFileRecord(const CNTFSVolume *volume);
	virtual ~CFileRecord();

	friend class CAttrBase;
#if	_MSC_VER <= 1200
	// Walk around VC6.0 compiler defect
	friend class CAttr_AttrList<CAttrResident>;
	friend class CAttr_AttrList<CAttrNonResident>;
#else
	template <class TYPE_RESIDENT> friend class CAttr_AttrList;		// Won't compiler in VC6.0, why?
#endif

private:
	const CNTFSVolume *Volume;
	FILE_RECORD_HEADER *FileRecord;
	ULONGLONG FileReference;
	ATTR_RAW_CALLBACK AttrRawCallBack[ATTR_NUMS];
	DWORD AttrMask;
	CAttrList AttrList[ATTR_NUMS];	// Attributes

	void ClearAttrs();
	BOOL PatchUS(WORD *sector, int sectors, WORD usn, WORD *usarray);
	__inline void UserCallBack(DWORD attType, ATTR_HEADER_COMMON *ahc, BOOL *bDiscard);
	CAttrBase* AllocAttr(ATTR_HEADER_COMMON *ahc, BOOL *bUnhandled);
	BOOL ParseAttr(ATTR_HEADER_COMMON *ahc);
	FILE_RECORD_HEADER* ReadFileRecord(ULONGLONG &fileRef);
	BOOL VisitIndexBlock(const ULONGLONG &vcn, const _TCHAR *fileName, CIndexEntry &ieFound) const;
	void TraverseSubNode(const ULONGLONG &vcn, SUBENTRY_CALLBACK seCallBack) const;

public:
	BOOL ParseFileRecord(ULONGLONG fileRef);
	BOOL ParseAttrs();

	BOOL InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb);
	__inline void ClearAttrRawCB();

	__inline void SetAttrMask(DWORD mask);
	void TraverseAttrs(ATTRS_CALLBACK attrCallBack, void *context);
	__inline const CAttrBase* FindFirstAttr(DWORD attrType) const;
	const CAttrBase* FindNextAttr(DWORD attrType) const;

	int GetFileName(_TCHAR *buf, DWORD bufLen) const;
	__inline ULONGLONG GetFileSize() const;
	void GetFileTime(FILETIME *writeTm, FILETIME *createTm = NULL, FILETIME *accessTm = NULL) const;

	void TraverseSubEntries(SUBENTRY_CALLBACK seCallBack) const;
	__inline const BOOL FindSubEntry(const _TCHAR *fileName, CIndexEntry &ieFound) const;
	const CAttrBase* FindStream(_TCHAR *name = NULL);

	__inline BOOL IsDeleted() const;
	__inline BOOL IsDirectory() const;
	__inline BOOL IsReadOnly() const;
	__inline BOOL IsHidden() const;
	__inline BOOL IsSystem() const;
	__inline BOOL IsCompressed() const;
	__inline BOOL IsEncrypted() const;
	__inline BOOL IsSparse() const;
};	// CFileRecord


#include "NTFS_Attribute.h"


CFileRecord::CFileRecord(const CNTFSVolume *volume)
{
	_ASSERT(volume);
	Volume = volume;
	FileRecord = NULL;
	FileReference = (ULONGLONG)-1;

	ClearAttrRawCB();

	// Default to parse all attributes
	AttrMask = MASK_ALL;
}

CFileRecord::~CFileRecord()
{
	ClearAttrs();

	if (FileRecord)
		delete FileRecord;
}

// Free all CAttr_xxx
void CFileRecord::ClearAttrs()
{
	for (int i=0; i<ATTR_NUMS; i++)
	{
		AttrList[i].RemoveAll();
	}
}

// Verify US and update sectors
BOOL CFileRecord::PatchUS(WORD *sector, int sectors, WORD usn, WORD *usarray)
{
	int i;

	for (i=0; i<sectors; i++)
	{
		sector += ((Volume->SectorSize>>1) - 1);
		if (*sector != usn)
			return FALSE;	// USN error
		*sector = usarray[i];	// Write back correct data
		sector++;
	}
	return TRUE;
}

// Call user defined Callback routines for an attribute
__inline void CFileRecord::UserCallBack(DWORD attType, ATTR_HEADER_COMMON *ahc, BOOL *bDiscard)
{
	*bDiscard = FALSE;

	if (AttrRawCallBack[attType])
		AttrRawCallBack[attType](ahc, bDiscard);
	else if (Volume->AttrRawCallBack[attType])
		Volume->AttrRawCallBack[attType](ahc, bDiscard);
}

CAttrBase* CFileRecord::AllocAttr(ATTR_HEADER_COMMON *ahc, BOOL *bUnhandled)
{
	switch (ahc->Type)
	{
		case ATTR_TYPE_STANDARD_INFORMATION:
			return new CAttr_StdInfo(ahc, this);

		case ATTR_TYPE_ATTRIBUTE_LIST:
			if (ahc->NonResident)
				return new CAttr_AttrList<CAttrNonResident>(ahc, this);
			else
				return new CAttr_AttrList<CAttrResident>(ahc, this);

		case ATTR_TYPE_FILE_NAME:
			return new CAttr_FileName(ahc, this);

		case ATTR_TYPE_VOLUME_NAME:
			return new CAttr_VolName(ahc, this);

		case ATTR_TYPE_VOLUME_INFORMATION:
			return new CAttr_VolInfo(ahc, this);

		case ATTR_TYPE_DATA:
			if (ahc->NonResident)
				return new CAttr_Data<CAttrNonResident>(ahc, this);
			else
				return new CAttr_Data<CAttrResident>(ahc, this);

		case ATTR_TYPE_INDEX_ROOT:
			return new CAttr_IndexRoot(ahc, this);

		case ATTR_TYPE_INDEX_ALLOCATION:
			return new CAttr_IndexAlloc(ahc, this);

		case ATTR_TYPE_BITMAP:
			if (ahc->NonResident)
				return new CAttr_Bitmap<CAttrNonResident>(ahc, this);
			else
				// Resident Bitmap may exist in a directory's FileRecord
				// or in $MFT for a very small volume in theory
				return new CAttr_Bitmap<CAttrResident>(ahc, this);

		// Unhandled Attributes
		default:
			*bUnhandled = TRUE;
			if (ahc->NonResident)
				return new CAttrNonResident(ahc, this);
			else
				return new CAttrResident(ahc, this);
	}
}

// Parse a single Attribute
// Return False on error
BOOL CFileRecord::ParseAttr(ATTR_HEADER_COMMON *ahc)
{
	DWORD attrIndex = ATTR_INDEX(ahc->Type);
	if (attrIndex < ATTR_NUMS)
	{
		BOOL bDiscard = FALSE;
		UserCallBack(attrIndex, ahc, &bDiscard);

		if (!bDiscard)
		{
			BOOL bUnhandled = FALSE;
			CAttrBase *attr = AllocAttr(ahc, &bUnhandled);
			if (attr)
			{
				if (bUnhandled)
				{
					NTFS_TRACE1("Unhandled attribute: 0x%04X\n", ahc->Type);
				}
				AttrList[attrIndex].InsertEntry(attr);
				return TRUE;
			}
			else
			{
				NTFS_TRACE1("Attribute Parse error: 0x%04X\n", ahc->Type);
				return FALSE;
			}
		}
		else
		{
			NTFS_TRACE1("User Callback has processed this Attribute: 0x%04X\n", ahc->Type);
			return TRUE;
		}
	}
	else
	{
		NTFS_TRACE1("Invalid Attribute Type: 0x%04X\n", ahc->Type);
		return FALSE;
	}
}

// Read File Record
FILE_RECORD_HEADER* CFileRecord::ReadFileRecord(ULONGLONG &fileRef)
{
	FILE_RECORD_HEADER *fr = NULL;
	DWORD len;

	if (fileRef < MFT_IDX_USER || Volume->MFTData == NULL)
	{
		// Take as continuous disk allocation
		LARGE_INTEGER frAddr;
		frAddr.QuadPart = Volume->MFTAddr + (Volume->FileRecordSize) * fileRef;
		frAddr.LowPart = SetFilePointer(Volume->hVolume, frAddr.LowPart, &frAddr.HighPart, FILE_BEGIN);

		if (frAddr.LowPart == DWORD(-1) && GetLastError() != NO_ERROR)
			return FALSE;
		else
		{
			fr = (FILE_RECORD_HEADER*)new BYTE[Volume->FileRecordSize];

			if (ReadFile(Volume->hVolume, fr, Volume->FileRecordSize, &len, NULL)
				&& len==Volume->FileRecordSize)
				return fr;
			else
			{
				delete fr;
				return NULL;
			}
		}
	}
	else
	{
		// May be fragmented $MFT
		ULONGLONG frAddr;
		frAddr = (Volume->FileRecordSize) * fileRef;

		fr = (FILE_RECORD_HEADER*)new BYTE[Volume->FileRecordSize];

		if (Volume->MFTData->ReadData(frAddr, fr, Volume->FileRecordSize, &len)
			&& len == Volume->FileRecordSize)
			return fr;
		else
		{
			delete fr;
			return NULL;
		}
	}
}

// Read File Record, verify and patch the US (update sequence)
BOOL CFileRecord::ParseFileRecord(ULONGLONG fileRef)
{
	// Clear previous data
	ClearAttrs();
	if (FileRecord)
	{
		delete FileRecord;
		FileRecord = NULL;
	}

	FILE_RECORD_HEADER *fr = ReadFileRecord(fileRef);
	if (fr == NULL)
	{
		NTFS_TRACE1("Cannot read file record %I64u\n", fileRef);

		FileReference = (ULONGLONG)-1;
	}
	else
	{
		FileReference = fileRef;

		if (fr->Magic == FILE_RECORD_MAGIC)
		{
			// Patch US
			WORD *usnaddr = (WORD*)((BYTE*)fr + fr->OffsetOfUS);
			WORD usn = *usnaddr;
			WORD *usarray = usnaddr + 1;
			if (PatchUS((WORD*)fr, Volume->FileRecordSize/Volume->SectorSize, usn, usarray))
			{
				NTFS_TRACE1("File Record %I64u Found\n", fileRef);
				FileRecord = fr;

				return TRUE;
			}
			else
			{
				NTFS_TRACE("Update Sequence Number error\n");
			}
		}
		else
		{
			NTFS_TRACE("Invalid file record\n");
		}

		delete fr;
	}

	return FALSE;
}

// Visit IndexBlocks recursivly to find a specific FileName
BOOL CFileRecord::VisitIndexBlock(const ULONGLONG &vcn, const _TCHAR *fileName, CIndexEntry &ieFound) const
{
	CAttr_IndexAlloc *ia = (CAttr_IndexAlloc*)FindFirstAttr(ATTR_TYPE_INDEX_ALLOCATION);
	if (ia == NULL)
		return FALSE;

	CIndexBlock ib;
	if (ia->ParseIndexBlock(vcn, ib))
	{
		CIndexEntry *ie = ib.FindFirstEntry();
		while (ie)
		{
			if (ie->HasName())
			{
				// Compare name
				int i = ie->Compare(fileName);
				if (i == 0)
				{
					ieFound = *ie;
					return TRUE;
				}
				else if (i < 0)		// fileName is smaller than IndexEntry
				{
					// Visit SubNode
					if (ie->IsSubNodePtr())
					{
						// Search in SubNode (IndexBlock), recursive call
						if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
							return TRUE;
					}
					else
						return FALSE;	// not found
				}
				// Just step forward if fileName is bigger than IndexEntry
			}
			else if (ie->IsSubNodePtr())
			{
				// Search in SubNode (IndexBlock), recursive call
				if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
					return TRUE;
			}

			ie = ib.FindNextEntry();
		}
	}

	return FALSE;
}

// Traverse SubNode recursivly in ascending order
// Call user defined callback routine once found an subentry
void CFileRecord::TraverseSubNode(const ULONGLONG &vcn, SUBENTRY_CALLBACK seCallBack) const
{
	CAttr_IndexAlloc *ia = (CAttr_IndexAlloc*)FindFirstAttr(ATTR_TYPE_INDEX_ALLOCATION);
	if (ia == NULL)
		return;

	CIndexBlock ib;
	if (ia->ParseIndexBlock(vcn, ib))
	{
		CIndexEntry *ie = ib.FindFirstEntry();
		while (ie)
		{
			if (ie->IsSubNodePtr())
				TraverseSubNode(ie->GetSubNodeVCN(), seCallBack);	// recursive call

			if (ie->HasName())
				seCallBack(ie);

			ie = ib.FindNextEntry();
		}
	}
}

// Parse all the attributes in a File Record
// And insert them into a link list
BOOL CFileRecord::ParseAttrs()
{
	_ASSERT(FileRecord);

	// Clear previous data
	ClearAttrs();

	// Visit all attributes

	DWORD dataPtr = 0;	// guard if data exceeds FileRecordSize bounds
	ATTR_HEADER_COMMON *ahc = (ATTR_HEADER_COMMON*)((BYTE*)FileRecord + FileRecord->OffsetOfAttr);
	dataPtr += FileRecord->OffsetOfAttr;

	while (ahc->Type != (DWORD)-1 && (dataPtr+ahc->TotalSize) <= Volume->FileRecordSize)
	{
		if (ATTR_MASK(ahc->Type) & AttrMask)	// Skip unwanted attributes
		{
			if (!ParseAttr(ahc))	// Parse error
				return FALSE;

			if (IsEncrypted() || IsCompressed())
			{
				NTFS_TRACE("Compressed and Encrypted file not supported yet !\n");
				return FALSE;
			}
		}

		dataPtr += ahc->TotalSize;
		ahc = (ATTR_HEADER_COMMON*)((BYTE*)ahc + ahc->TotalSize);	// next attribute
	}

	return TRUE;
}

// Install Attribute raw data CallBack routines for a single File Record
BOOL CFileRecord::InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb)
{
	DWORD atIdx = ATTR_INDEX(attrType);
	if (atIdx < ATTR_NUMS)
	{
		AttrRawCallBack[atIdx] = cb;
		return TRUE;
	}
	else
		return FALSE;
}

// Clear all Attribute CallBack routines
__inline void CFileRecord::ClearAttrRawCB()
{
	for (int i = 0; i < ATTR_NUMS; i ++)
		AttrRawCallBack[i] = NULL;
}

// Choose attributes to handle, unwanted attributes will be discarded silently
__inline void CFileRecord::SetAttrMask(DWORD mask)
{
	// Standard Information and Attribute List is needed always
	AttrMask = mask | MASK_STANDARD_INFORMATION | MASK_ATTRIBUTE_LIST;
}

// Traverse all Attribute and return CAttr_xxx classes to User Callback routine
void CFileRecord::TraverseAttrs(ATTRS_CALLBACK attrCallBack, void *context)
{
	_ASSERT(attrCallBack);

	for (int i = 0; i < ATTR_NUMS; i ++)
	{
		if (AttrMask & (((DWORD)1)<<i))	// skip masked attributes
		{
			const CAttrBase *ab = AttrList[i].FindFirstEntry();
			while (ab)
			{
				BOOL bStop;
				bStop = FALSE;
				attrCallBack(ab, context, &bStop);
				if (bStop)
					return;

				ab = AttrList[i].FindNextEntry();
			}
		}
	}
}

// Find Attributes
__inline const CAttrBase* CFileRecord::FindFirstAttr(DWORD attrType) const
{
	DWORD attrIdx = ATTR_INDEX(attrType);

	return attrIdx < ATTR_NUMS ? AttrList[attrIdx].FindFirstEntry() : NULL;
}

const CAttrBase* CFileRecord::FindNextAttr(DWORD attrType) const
{
	DWORD attrIdx = ATTR_INDEX(attrType);

	return attrIdx < ATTR_NUMS ? AttrList[attrIdx].FindNextEntry() : NULL;
}

// Get File Name (First Win32 name)
int CFileRecord::GetFileName(_TCHAR *buf, DWORD bufLen) const
{
	// A file may have several filenames
	// Return the first Win32 filename
	CAttr_FileName *fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
	while (fn)
	{
		if (fn->IsWin32Name())
		{
			int len = fn->GetFileName(buf, bufLen);
			if (len != 0)
				return len;	// success or fail
		}

		fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindNextEntry();
	}

	return 0;
}

// Get File Size
__inline ULONGLONG CFileRecord::GetFileSize() const
{
	CAttr_FileName *fn = (CAttr_FileName*)AttrList[ATTR_INDEX(ATTR_TYPE_FILE_NAME)].FindFirstEntry();
	return fn ? fn->GetFileSize() : 0;
}

// Get File Times
void CFileRecord::GetFileTime(FILETIME *writeTm, FILETIME *createTm, FILETIME *accessTm) const
{
	// Standard Information attribute hold the most updated file time
	CAttr_StdInfo *si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	if (si)
		si->GetFileTime(writeTm, createTm, accessTm);
	else
	{
		writeTm->dwHighDateTime = 0;
		writeTm->dwLowDateTime = 0;
		if (createTm)
		{
			createTm->dwHighDateTime = 0;
			createTm->dwLowDateTime = 0;
		}
		if (accessTm)
		{
			accessTm->dwHighDateTime = 0;
			accessTm->dwLowDateTime = 0;
		}
	}
}

// Traverse all sub directories and files contained
// Call user defined callback routine once found an entry
void CFileRecord::TraverseSubEntries(SUBENTRY_CALLBACK seCallBack) const
{
	_ASSERT(seCallBack);

	// Start traversing from IndexRoot (B+ tree root node)

	CAttr_IndexRoot* ir = (CAttr_IndexRoot*)FindFirstAttr(ATTR_TYPE_INDEX_ROOT);
	if (ir == NULL || !ir->IsFileName())
		return;

	CIndexEntryList *ieList = (CIndexEntryList*)ir;
	CIndexEntry *ie = ieList->FindFirstEntry();
	while (ie)
	{
		// Visit subnode first
		if (ie->IsSubNodePtr())
			TraverseSubNode(ie->GetSubNodeVCN(), seCallBack);

		if (ie->HasName())
			seCallBack(ie);

		ie = ieList->FindNextEntry();
	}
}

// Find a specific FileName from InexRoot described B+ tree
__inline const BOOL CFileRecord::FindSubEntry(const _TCHAR *fileName, CIndexEntry &ieFound) const
{
	// Start searching from IndexRoot (B+ tree root node)
	CAttr_IndexRoot *ir = (CAttr_IndexRoot*)FindFirstAttr(ATTR_TYPE_INDEX_ROOT);
	if (ir == NULL || !ir->IsFileName())
		return FALSE;

	CIndexEntryList *ieList = (CIndexEntryList*)ir;
	CIndexEntry *ie = ieList->FindFirstEntry();
	while (ie)
	{
		if (ie->HasName())
		{
			// Compare name
			int i = ie->Compare(fileName);
			if (i == 0)
			{
				ieFound = *ie;
				return TRUE;
			}
			else if (i < 0)		// fileName is smaller than IndexEntry
			{
				// Visit SubNode
				if (ie->IsSubNodePtr())
				{
					// Search in SubNode (IndexBlock)
					if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
						return TRUE;
				}
				else
					return FALSE;	// not found
			}
			// Just step forward if fileName is bigger than IndexEntry
		}
		else if (ie->IsSubNodePtr())
		{
			// Search in SubNode (IndexBlock)
			if (VisitIndexBlock(ie->GetSubNodeVCN(), fileName, ieFound))
				return TRUE;
		}

		ie = ieList->FindNextEntry();
	}

	return FALSE;
}

// Find Data attribute class of 
const CAttrBase* CFileRecord::FindStream(_TCHAR *name)
{
	const CAttrBase *data = FindFirstAttr(ATTR_TYPE_DATA);
	while (data)
	{
		if (data->IsUnNamed() && name == NULL)	// Unnamed stream
			break;
		if ((!data->IsUnNamed()) && name)	// Named stream
		{
			_TCHAR an[MAX_PATH];
			if (data->GetAttrName(an, MAX_PATH))
			{
				if (_tcscmp(an, name) == 0)
					break;
			}
		}

		data = FindNextAttr(ATTR_TYPE_DATA);
	}

	return data;
}

// Check if it's deleted or in use
__inline BOOL CFileRecord::IsDeleted() const
{
	return !(FileRecord->Flags & FILE_RECORD_FLAG_INUSE);
}

// Check if it's a directory
__inline BOOL CFileRecord::IsDirectory() const
{
	return FileRecord->Flags & FILE_RECORD_FLAG_DIR;
}

__inline BOOL CFileRecord::IsReadOnly() const
{
	// Standard Information attribute holds the most updated file time
	const CAttr_StdInfo *si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsReadOnly() : FALSE;
}

__inline BOOL CFileRecord::IsHidden() const
{
	const CAttr_StdInfo *si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsHidden() : FALSE;
}

__inline BOOL CFileRecord::IsSystem() const
{
	const CAttr_StdInfo *si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsSystem() : FALSE;
}

__inline BOOL CFileRecord::IsCompressed() const
{
	const CAttr_StdInfo *si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsCompressed() : FALSE;
}

__inline BOOL CFileRecord::IsEncrypted() const
{
	const CAttr_StdInfo *si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsEncrypted() : FALSE;
}

__inline BOOL CFileRecord::IsSparse() const
{
	const CAttr_StdInfo *si = (CAttr_StdInfo*)AttrList[ATTR_INDEX(ATTR_TYPE_STANDARD_INFORMATION)].FindFirstEntry();
	return si ? si->IsSparse() : FALSE;
}


///////////////////////////////////////
// NTFS Volume Implementation
///////////////////////////////////////
CNTFSVolume::CNTFSVolume(_TCHAR volume)
{
	hVolume = INVALID_HANDLE_VALUE;
	VolumeOK = FALSE;
	MFTRecord = NULL;
	MFTData = NULL;
	Version = 0;
	ClearAttrRawCB();

	if (!OpenVolume(volume))
		return;

	// Verify NTFS volume version (must >= 3.0)

	CFileRecord vol(this);
	vol.SetAttrMask(MASK_VOLUME_NAME | MASK_VOLUME_INFORMATION);
	if (!vol.ParseFileRecord(MFT_IDX_VOLUME))
		return;

	vol.ParseAttrs();
	CAttr_VolInfo *vi = (CAttr_VolInfo*)vol.FindFirstAttr(ATTR_TYPE_VOLUME_INFORMATION);
	if (!vi)
		return;

	Version = vi->GetVersion();
	NTFS_TRACE2("NTFS volume version: %u.%u\n", HIBYTE(Version), LOBYTE(Version));
	if (Version < 0x0300)	// NT4 ?
		return;

#ifdef	_DEBUG
	CAttr_VolName *vn = (CAttr_VolName*)vol.FindFirstAttr(ATTR_TYPE_VOLUME_NAME);
	if (vn)
	{
		char volname[MAX_PATH];
		if (vn->GetName(volname, MAX_PATH) > 0)
		{
			NTFS_TRACE1("NTFS volume name: %s\n", volname);
		}
	}
#endif

	VolumeOK = TRUE;

	MFTRecord = new CFileRecord(this);
	MFTRecord->SetAttrMask(MASK_DATA);
	if (MFTRecord->ParseFileRecord(MFT_IDX_MFT))
	{
		MFTRecord->ParseAttrs();
		MFTData = MFTRecord->FindFirstAttr(ATTR_TYPE_DATA);
		if (MFTData == NULL)
		{
			delete MFTRecord;
			MFTRecord = NULL;
		}
	}
}

CNTFSVolume::~CNTFSVolume()
{
	if (hVolume != INVALID_HANDLE_VALUE)
		CloseHandle(hVolume);

	if (MFTRecord)
		delete MFTRecord;
}

// Open a volume ('a' - 'z', 'A' - 'Z'), get volume handle and BPB
BOOL CNTFSVolume::OpenVolume(_TCHAR volume)
{
	// Verify parameter
	if (!_istalpha(volume))
	{
		NTFS_TRACE("Volume name error, should be like 'C', 'D'\n");
		return FALSE;
	}

	_TCHAR volumePath[7];
	_sntprintf(volumePath, 6, _T("\\\\.\\%c:"), volume);
	volumePath[6] = _T('\0');

	hVolume = CreateFile(volumePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
	if (hVolume != INVALID_HANDLE_VALUE)
	{
		DWORD num;
		NTFS_BPB bpb;

		// Read the first sector (boot sector)
		if (ReadFile(hVolume, &bpb, 512, &num, NULL) && num==512)
		{
			if (strncmp((const char*)bpb.Signature, NTFS_SIGNATURE, 8) == 0)
			{
				// Log important volume parameters

				SectorSize = bpb.BytesPerSector;
				NTFS_TRACE1("Sector Size = %u bytes\n", SectorSize);

				ClusterSize = SectorSize * bpb.SectorsPerCluster;
				NTFS_TRACE1("Cluster Size = %u bytes\n", ClusterSize);

				int sz = (char)bpb.ClustersPerFileRecord;
				if (sz > 0)
					FileRecordSize = ClusterSize * sz;
				else
					FileRecordSize = 1 << (-sz);
				NTFS_TRACE1("FileRecord Size = %u bytes\n", FileRecordSize);

				sz = (char)bpb.ClustersPerIndexBlock;
				if (sz > 0)
					IndexBlockSize = ClusterSize * sz;
				else
					IndexBlockSize = 1 << (-sz);
				NTFS_TRACE1("IndexBlock Size = %u bytes\n", IndexBlockSize);

				MFTAddr = bpb.LCN_MFT * ClusterSize;
				NTFS_TRACE1("MFT address = 0x%016I64X\n", MFTAddr);
			}
			else
			{
				NTFS_TRACE("Volume file system is not NTFS\n");
				goto IOError;
			}
		}
		else
		{
			NTFS_TRACE("Read boot sector error\n");
			goto IOError;
		}
	}
	else
	{
		NTFS_TRACE1("Cannnot open volume %c\n", (char)volume);
IOError:
		if (hVolume != INVALID_HANDLE_VALUE)
		{
			CloseHandle(hVolume);
			hVolume = INVALID_HANDLE_VALUE;
		}
		return FALSE;
	}

	return TRUE;
}

// Check if Volume is successfully opened
__inline BOOL CNTFSVolume::IsVolumeOK() const
{
	return VolumeOK;
}

// Get NTFS volume version
__inline WORD CNTFSVolume::GetVersion() const
{
	return Version;
}

// Get File Record count
__inline ULONGLONG CNTFSVolume::GetRecordsCount() const
{
	return (MFTData->GetDataSize() / FileRecordSize);
}

// Get BPB information

__inline DWORD CNTFSVolume::GetSectorSize() const
{
	return SectorSize;
}

__inline DWORD CNTFSVolume::GetClusterSize() const
{
	return ClusterSize;
}

__inline DWORD CNTFSVolume::GetFileRecordSize() const
{
	return FileRecordSize;
}

__inline DWORD CNTFSVolume::GetIndexBlockSize() const
{
	return IndexBlockSize;
}

// Get MFT starting address
__inline ULONGLONG CNTFSVolume::GetMFTAddr() const
{
	return MFTAddr;
}

// Install Attribute CallBack routines for the whole Volume
BOOL CNTFSVolume::InstallAttrRawCB(DWORD attrType, ATTR_RAW_CALLBACK cb)
{
	DWORD atIdx = ATTR_INDEX(attrType);
	if (atIdx < ATTR_NUMS)
	{
		AttrRawCallBack[atIdx] = cb;
		return TRUE;
	}
	else
		return FALSE;
}

// Clear all Attribute CallBack routines
__inline void CNTFSVolume::ClearAttrRawCB()
{
	for (int i = 0; i < ATTR_NUMS; i ++)
		AttrRawCallBack[i] = NULL;
}

#endif
