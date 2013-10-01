/*
 * NTFS data structures and definitions
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

#ifndef	__NTFS_DATATYPE_H_CYB70289
#define	__NTFS_DATATYPE_H_CYB70289

// NTFS Boot Sector BPB

#define	NTFS_SIGNATURE		"NTFS    "

#pragma pack(1)
typedef struct tagNTFS_BPB
{
	// jump instruction
	BYTE		Jmp[3];

	// signature
	BYTE		Signature[8];

	// BPB and extended BPB
	WORD		BytesPerSector;
	BYTE		SectorsPerCluster;
	WORD		ReservedSectors;
	BYTE		Zeros1[3];
	WORD		NotUsed1;
	BYTE		MediaDescriptor;
	WORD		Zeros2;
	WORD		SectorsPerTrack;
	WORD		NumberOfHeads;
	DWORD		HiddenSectors;
	DWORD		NotUsed2;
	DWORD		NotUsed3;
	ULONGLONG	TotalSectors;
	ULONGLONG	LCN_MFT;
	ULONGLONG	LCN_MFTMirr;
	DWORD		ClustersPerFileRecord;
	DWORD		ClustersPerIndexBlock;
	BYTE		VolumeSN[8];

	// boot code
	BYTE		Code[430];

	//0xAA55
	BYTE		_AA;
	BYTE		_55;
} NTFS_BPB;
#pragma pack()


// MFT Indexes
#define	MFT_IDX_MFT				0
#define	MFT_IDX_MFT_MIRR		1
#define	MFT_IDX_LOG_FILE		2
#define	MFT_IDX_VOLUME			3
#define	MFT_IDX_ATTR_DEF		4
#define	MFT_IDX_ROOT			5
#define	MFT_IDX_BITMAP			6
#define	MFT_IDX_BOOT			7
#define	MFT_IDX_BAD_CLUSTER		8
#define	MFT_IDX_SECURE			9
#define	MFT_IDX_UPCASE			10
#define	MFT_IDX_EXTEND			11
#define	MFT_IDX_RESERVED12		12
#define	MFT_IDX_RESERVED13		13
#define	MFT_IDX_RESERVED14		14
#define	MFT_IDX_RESERVED15		15
#define	MFT_IDX_USER			16


/******************************
		File Record
	---------------------
	| File Record Header|
	---------------------
	|    Attribute 1    |
	---------------------
	|    Attribute 2    |
	---------------------
	|      ......       |
	---------------------
	|     0xFFFFFFFF    |
	---------------------
*******************************/

// File Record Header

#define	FILE_RECORD_MAGIC		'ELIF'
#define	FILE_RECORD_FLAG_INUSE	0x01	// File record is in use
#define	FILE_RECORD_FLAG_DIR	0x02	// File record is a directory

typedef struct tagFILE_RECORD_HEADER
{
	DWORD		Magic;			// "FILE"
	WORD		OffsetOfUS;		// Offset of Update Sequence
	WORD		SizeOfUS;		// Size in words of Update Sequence Number & Array
	ULONGLONG	LSN;			// $LogFile Sequence Number
	WORD		SeqNo;			// Sequence number
	WORD		Hardlinks;		// Hard link count
	WORD		OffsetOfAttr;	// Offset of the first Attribute
	WORD		Flags;			// Flags
	DWORD		RealSize;		// Real size of the FILE record
	DWORD		AllocSize;		// Allocated size of the FILE record
	ULONGLONG	RefToBase;		// File reference to the base FILE record
	WORD		NextAttrId;		// Next Attribute Id
	WORD		Align;			// Align to 4 byte boundary
	DWORD		RecordNo;		// Number of this MFT Record
} FILE_RECORD_HEADER;


/******************************
		Attribute
	--------------------
	| Attribute Header |
	--------------------
	|  Attribute Data  |
	--------------------
*******************************/

// Attribute Header

#define	ATTR_TYPE_STANDARD_INFORMATION	0x10
#define	ATTR_TYPE_ATTRIBUTE_LIST		0x20
#define	ATTR_TYPE_FILE_NAME				0x30
#define	ATTR_TYPE_OBJECT_ID				0x40
#define	ATTR_TYPE_SECURITY_DESCRIPTOR	0x50
#define	ATTR_TYPE_VOLUME_NAME			0x60
#define	ATTR_TYPE_VOLUME_INFORMATION	0x70
#define	ATTR_TYPE_DATA					0x80
#define	ATTR_TYPE_INDEX_ROOT			0x90
#define	ATTR_TYPE_INDEX_ALLOCATION		0xA0
#define	ATTR_TYPE_BITMAP				0xB0
#define	ATTR_TYPE_REPARSE_POINT			0xC0
#define	ATTR_TYPE_EA_INFORMATION		0xD0
#define	ATTR_TYPE_EA					0xE0
#define	ATTR_TYPE_LOGGED_UTILITY_STREAM	0x100

#define	ATTR_FLAG_COMPRESSED			0x0001
#define	ATTR_FLAG_ENCRYPTED				0x4000
#define	ATTR_FLAG_SPARSE				0x8000

typedef	struct tagATTR_HEADER_COMMON
{
	DWORD		Type;			// Attribute Type
	DWORD		TotalSize;		// Length (including this header)
	BYTE		NonResident;	// 0 - resident, 1 - non resident
	BYTE		NameLength;		// name length in words
	WORD		NameOffset;		// offset to the name
	WORD		Flags;			// Flags
	WORD		Id;				// Attribute Id
} ATTR_HEADER_COMMON;

typedef	struct tagATTR_HEADER_RESIDENT
{
	ATTR_HEADER_COMMON	Header;			// Common data structure
	DWORD				AttrSize;		// Length of the attribute body
	WORD				AttrOffset;		// Offset to the Attribute
	BYTE				IndexedFlag;	// Indexed flag
	BYTE				Padding;		// Padding
} ATTR_HEADER_RESIDENT;

typedef struct tagATTR_HEADER_NON_RESIDENT
{
	ATTR_HEADER_COMMON	Header;			// Common data structure
	ULONGLONG			StartVCN;		// Starting VCN
	ULONGLONG			LastVCN;		// Last VCN
	WORD				DataRunOffset;	// Offset to the Data Runs
	WORD				CompUnitSize;	// Compression unit size
	DWORD				Padding;		// Padding
	ULONGLONG			AllocSize;		// Allocated size of the attribute
	ULONGLONG			RealSize;		// Real size of the attribute
	ULONGLONG			IniSize;		// Initialized data size of the stream 
} ATTR_HEADER_NON_RESIDENT;


// Attribute: STANDARD_INFORMATION

#define	ATTR_STDINFO_PERMISSION_READONLY	0x00000001
#define	ATTR_STDINFO_PERMISSION_HIDDEN		0x00000002
#define	ATTR_STDINFO_PERMISSION_SYSTEM		0x00000004
#define	ATTR_STDINFO_PERMISSION_ARCHIVE		0x00000020
#define	ATTR_STDINFO_PERMISSION_DEVICE		0x00000040
#define	ATTR_STDINFO_PERMISSION_NORMAL		0x00000080
#define	ATTR_STDINFO_PERMISSION_TEMP		0x00000100
#define	ATTR_STDINFO_PERMISSION_SPARSE		0x00000200
#define	ATTR_STDINFO_PERMISSION_REPARSE		0x00000400
#define	ATTR_STDINFO_PERMISSION_COMPRESSED	0x00000800
#define	ATTR_STDINFO_PERMISSION_OFFLINE		0x00001000
#define	ATTR_STDINFO_PERMISSION_NCI			0x00002000
#define	ATTR_STDINFO_PERMISSION_ENCRYPTED	0x00004000

typedef struct tagATTR_STANDARD_INFORMATION
{
	ULONGLONG	CreateTime;		// File creation time
	ULONGLONG	AlterTime;		// File altered time
	ULONGLONG	MFTTime;		// MFT changed time
	ULONGLONG	ReadTime;		// File read time
	DWORD		Permission;		// Dos file permission
	DWORD		MaxVersionNo;	// Maxim number of file versions
	DWORD		VersionNo;		// File version number
	DWORD		ClassId;		// Class Id
	DWORD		OwnerId;		// Owner Id
	DWORD		SecurityId;		// Security Id
	ULONGLONG	QuotaCharged;	// Quota charged
	ULONGLONG	USN;			// USN Journel
} ATTR_STANDARD_INFORMATION;


// Attribute: ATTRIBUTE_LIST

typedef struct tagATTR_ATTRIBUTE_LIST
{
	DWORD		AttrType;		// Attribute type
	WORD		RecordSize;		// Record length
	BYTE		NameLength;		// Name length in characters
	BYTE		NameOffset;		// Name offset
	ULONGLONG	StartVCN;		// Start VCN
	ULONGLONG	BaseRef;		// Base file reference to the attribute
	WORD		AttrId;			// Attribute Id
} ATTR_ATTRIBUTE_LIST;

// Attribute: FILE_NAME

#define	ATTR_FILENAME_FLAG_READONLY		0x00000001
#define	ATTR_FILENAME_FLAG_HIDDEN		0x00000002
#define	ATTR_FILENAME_FLAG_SYSTEM		0x00000004
#define	ATTR_FILENAME_FLAG_ARCHIVE		0x00000020
#define	ATTR_FILENAME_FLAG_DEVICE		0x00000040
#define	ATTR_FILENAME_FLAG_NORMAL		0x00000080
#define	ATTR_FILENAME_FLAG_TEMP			0x00000100
#define	ATTR_FILENAME_FLAG_SPARSE		0x00000200
#define	ATTR_FILENAME_FLAG_REPARSE		0x00000400
#define	ATTR_FILENAME_FLAG_COMPRESSED	0x00000800
#define	ATTR_FILENAME_FLAG_OFFLINE		0x00001000
#define	ATTR_FILENAME_FLAG_NCI			0x00002000
#define	ATTR_FILENAME_FLAG_ENCRYPTED	0x00004000
#define	ATTR_FILENAME_FLAG_DIRECTORY	0x10000000
#define	ATTR_FILENAME_FLAG_INDEXVIEW	0x20000000

#define	ATTR_FILENAME_NAMESPACE_POSIX	0x00
#define	ATTR_FILENAME_NAMESPACE_WIN32	0x01
#define	ATTR_FILENAME_NAMESPACE_DOS		0x02

typedef struct tagATTR_FILE_NAME
{
	ULONGLONG	ParentRef;		// File reference to the parent directory
	ULONGLONG	CreateTime;		// File creation time
	ULONGLONG	AlterTime;		// File altered time
	ULONGLONG	MFTTime;		// MFT changed time
	ULONGLONG	ReadTime;		// File read time
	ULONGLONG	AllocSize;		// Allocated size of the file
	ULONGLONG	RealSize;		// Real size of the file
	DWORD		Flags;			// Flags
	DWORD		ER;				// Used by EAs and Reparse
	BYTE		NameLength;		// Filename length in characters
	BYTE		NameSpace;		// Filename space
	WORD		Name[1];		// Filename
} ATTR_FILE_NAME;


// Attribute: VOLUME_INFORMATION

#define	ATTR_VOLINFO_FLAG_DIRTY		0x0001	// Dirty
#define	ATTR_VOLINFO_FLAG_RLF		0x0002	// Resize logfile
#define	ATTR_VOLINFO_FLAG_UOM		0x0004	// Upgrade on mount
#define	ATTR_VOLINFO_FLAG_MONT		0x0008	// Mounted on NT4
#define	ATTR_VOLINFO_FLAG_DUSN		0x0010	// Delete USN underway
#define	ATTR_VOLINFO_FLAG_ROI		0x0020	// Repair object Ids
#define	ATTR_VOLINFO_FLAG_MBC		0x8000	// Modified by chkdsk

typedef struct tagATTR_VOLUME_INFORMATION
{
	BYTE	Reserved1[8];	// Always 0 ?
	BYTE	MajorVersion;	// Major version
	BYTE	MinorVersion;	// Minor version
	WORD	Flags;			// Flags
	BYTE	Reserved2[4];	// Always 0 ?
} ATTR_VOLUME_INFORMATION;


// Attribute: INDEX_ROOT
/******************************
		INDEX_ROOT
	---------------------
	| Index Root Header |
	---------------------
	|    Index Header   |
	---------------------
	|    Index Entry    |
	---------------------
	|    Index Entry    |
	---------------------
	|      ......       |
	---------------------
*******************************/

#define	ATTR_INDEXROOT_FLAG_SMALL	0x00	// Fits in Index Root File Record
#define	ATTR_INDEXROOT_FLAG_LARGE	0x01	// Index Allocation and Bitmap needed

typedef struct tagATTR_INDEX_ROOT
{
	// Index Root Header
	DWORD		AttrType;			// Attribute type (ATTR_TYPE_FILE_NAME: Directory, 0: Index View)
	DWORD		CollRule;			// Collation rule
	DWORD		IBSize;				// Size of index block
	BYTE		ClustersPerIB;		// Clusters per index block (same as BPB?)
	BYTE		Padding1[3];		// Padding
	// Index Header
	DWORD		EntryOffset;		// Offset to the first index entry, relative to this address(0x10)
	DWORD		TotalEntrySize;		// Total size of the index entries
	DWORD		AllocEntrySize;		// Allocated size of the index entries
	BYTE		Flags;				// Flags
	BYTE		Padding2[3];		// Padding
} ATTR_INDEX_ROOT;


// INDEX ENTRY

#define	INDEX_ENTRY_FLAG_SUBNODE	0x01	// Index entry points to a sub-node
#define	INDEX_ENTRY_FLAG_LAST		0x02	// Last index entry in the node, no Stream

typedef struct tagINDEX_ENTRY
{
	ULONGLONG	FileReference;	// Low 6B: MFT record index, High 2B: MFT record sequence number
	WORD		Size;			// Length of the index entry
	WORD		StreamSize;		// Length of the stream
	BYTE		Flags;			// Flags
	BYTE		Padding[3];		// Padding
	BYTE		Stream[1];		// Stream
	// VCN of the sub node in Index Allocation, Offset = Size - 8
} INDEX_ENTRY;


// INDEX BLOCK
/******************************
		 INDEX_BLOCK
	-----------------------
	|  Index Block Header |
	-----------------------
	|     Index Header    |
	-----------------------
	|     Index Entry     |
	-----------------------
	|     Index Entry     |
	-----------------------
	|       ......        |
	-----------------------
*******************************/

#define	INDEX_BLOCK_MAGIC		'XDNI'

typedef struct tagINDEX_BLOCK
{
	// Index Block Header
	DWORD		Magic;			// "INDX"
	WORD		OffsetOfUS;		// Offset of Update Sequence
	WORD		SizeOfUS;		// Size in words of Update Sequence Number & Array
	ULONGLONG	LSN;			// $LogFile Sequence Number
	ULONGLONG	VCN;			// VCN of this index block in the index allocation
	// Index Header
	DWORD		EntryOffset;	// Offset of the index entries, relative to this address(0x18)
	DWORD		TotalEntrySize;	// Total size of the index entries
	DWORD		AllocEntrySize;	// Allocated size of index entries
	BYTE		NotLeaf;		// 1 if not leaf node (has children)
	BYTE		Padding[3];		// Padding
} INDEX_BLOCK;

#endif
