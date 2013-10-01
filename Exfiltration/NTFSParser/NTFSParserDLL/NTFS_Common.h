/*
 * NTFS Class common definitions
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

#ifndef	__NTFS_COMMON_H_CYB70289
#define	__NTFS_COMMON_H_CYB70289

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <crtdbg.h>

#include "NTFS_DataType.h"

#define	ATTR_NUMS		16				// Attribute Types count
#define	ATTR_INDEX(at)	(((at)>>4)-1)	// Attribute Type to Index, eg. 0x10->0, 0x30->2
#define	ATTR_MASK(at)	(((DWORD)1)<<ATTR_INDEX(at))	// Attribute Bit Mask

// Bit masks of Attributes
#define	MASK_STANDARD_INFORMATION	ATTR_MASK(ATTR_TYPE_STANDARD_INFORMATION)
#define	MASK_ATTRIBUTE_LIST			ATTR_MASK(ATTR_TYPE_ATTRIBUTE_LIST)
#define	MASK_FILE_NAME				ATTR_MASK(ATTR_TYPE_FILE_NAME)
#define	MASK_OBJECT_ID				ATTR_MASK(ATTR_TYPE_OBJECT_ID)
#define	MASK_SECURITY_DESCRIPTOR	ATTR_MASK(ATTR_TYPE_SECURITY_DESCRIPTOR)
#define	MASK_VOLUME_NAME			ATTR_MASK(ATTR_TYPE_VOLUME_NAME)
#define	MASK_VOLUME_INFORMATION		ATTR_MASK(ATTR_TYPE_VOLUME_INFORMATION)
#define	MASK_DATA					ATTR_MASK(ATTR_TYPE_DATA)
#define	MASK_INDEX_ROOT				ATTR_MASK(ATTR_TYPE_INDEX_ROOT)
#define	MASK_INDEX_ALLOCATION		ATTR_MASK(ATTR_TYPE_INDEX_ALLOCATION)
#define	MASK_BITMAP					ATTR_MASK(ATTR_TYPE_BITMAP)
#define	MASK_REPARSE_POINT			ATTR_MASK(ATTR_TYPE_REPARSE_POINT)
#define	MASK_EA_INFORMATION			ATTR_MASK(ATTR_TYPE_EA_INFORMATION)
#define	MASK_EA						ATTR_MASK(ATTR_TYPE_EA)
#define	MASK_LOGGED_UTILITY_STREAM	ATTR_MASK(ATTR_TYPE_LOGGED_UTILITY_STREAM)

#define	MASK_ALL					((DWORD)-1)

#define	NTFS_TRACE(t1)					_RPT0(_CRT_WARN, t1)
#define	NTFS_TRACE1(t1, t2)				_RPT1(_CRT_WARN, t1, t2)
#define	NTFS_TRACE2(t1, t2, t3)			_RPT2(_CRT_WARN, t1, t2, t3)
#define	NTFS_TRACE3(t1, t2, t3, t4)		_RPT3(_CRT_WARN, t1, t2, t3, t4)
#define	NTFS_TRACE4(t1, t2, t3, t4, t5)	_RPT4(_CRT_WARN, t1, t2, t3, t4, t5)

// User defined Callback routines to process raw attribute data
// Set bDiscard to TRUE if this Attribute is to be discarded
// Set bDiscard to FALSE to let CFileRecord process it
typedef void (*ATTR_RAW_CALLBACK)(const ATTR_HEADER_COMMON *attrHead, BOOL *bDiscard);

// User defined Callback routine to handle CFileRecord parsed attributes
// Will be called by CFileRecord::TraverseAttrs() for each attribute
// attrClass is the according attribute's wrapping class, CAttr_xxx
// Set bStop to TRUE if don't want to continue
// Set bStop to FALSE to continue processing
class CAttrBase;
typedef void (*ATTRS_CALLBACK)(const CAttrBase *attr, void *context, BOOL *bStop);

// User defined Callback routine to handle Directory traversing
// Will be called by CFileRecord::TraverseSubEntries for each sub entry
class CIndexEntry;
typedef void (*SUBENTRY_CALLBACK)(const CIndexEntry *ie);


// List Entry
template <class ENTRY_TYPE>
struct NTSLIST_ENTRY
{
	NTSLIST_ENTRY	*Next;
	ENTRY_TYPE		*Entry;
};

// List Entry Smart Pointer
template <class ENTRY_TYPE>
class CEntrySmartPtr
{
public:
	CEntrySmartPtr(ENTRY_TYPE *ptr = NULL)
	{
		EntryPtr = ptr;
	}

	virtual ~CEntrySmartPtr()
	{
		if (EntryPtr)
			delete EntryPtr;
	}

private:
	const ENTRY_TYPE *EntryPtr;

public:
	__inline CEntrySmartPtr<ENTRY_TYPE> operator = (const ENTRY_TYPE* ptr)
	{
		// Delete previous pointer if allocated
		if (EntryPtr)
			delete EntryPtr;

		EntryPtr = ptr;

		return *this;
	}

	__inline const ENTRY_TYPE* operator->() const
	{
		_ASSERT(EntryPtr);
		return EntryPtr;
	}

	__inline BOOL IsValid() const
	{
		return EntryPtr != NULL;
	}
};

//////////////////////////////////////
// Single list implementation
//////////////////////////////////////
template <class ENTRY_TYPE>
class CSList
{
public:
	CSList()
	{
		ListHead = ListTail = NULL;
		ListCurrent = NULL;
		EntryCount = 0;
	}

	virtual ~CSList()
	{
		RemoveAll();
	}

private:
	int EntryCount;
	NTSLIST_ENTRY<ENTRY_TYPE> *ListHead;
	NTSLIST_ENTRY<ENTRY_TYPE> *ListTail;
	NTSLIST_ENTRY<ENTRY_TYPE> *ListCurrent;

public:
	// Get entry count
	__inline int GetCount() const
	{
		return EntryCount;
	}

	// Insert to tail
	BOOL InsertEntry(ENTRY_TYPE *entry)
	{
		NTSLIST_ENTRY<ENTRY_TYPE> *le = new NTSLIST_ENTRY<ENTRY_TYPE>;
		if (!le)
			return FALSE;

		le->Entry = entry;
		le->Next = NULL;

		if (ListTail == NULL)
			ListHead = le;		// Empty list
		else
			ListTail->Next = le;

		ListTail = le;

		EntryCount++;
		return TRUE;
	}

	// Remove all entries
	void RemoveAll()
	{
		while (ListHead)
		{
			ListCurrent = ListHead->Next;
			delete ListHead->Entry;
			delete ListHead;

			ListHead = ListCurrent;
		}

		ListHead = ListTail = NULL;
		ListCurrent = NULL;
		EntryCount = 0;
	}

	// Find first entry
	__inline ENTRY_TYPE *FindFirstEntry() const
	{
		((CSList<ENTRY_TYPE>*)this)->ListCurrent = ListHead;

		if (ListCurrent)
			return ListCurrent->Entry;
		else
			return NULL;
	}

	// Find next entry
	__inline ENTRY_TYPE *FindNextEntry() const
	{
		if (ListCurrent)
			((CSList<ENTRY_TYPE>*)this)->ListCurrent = ListCurrent->Next;

		if (ListCurrent)
			return ListCurrent->Entry;
		else
			return NULL;
	}

	// Throw all entries
	// Caution! All entries are just thrown without free
	__inline void ThrowAll()
	{
		ListHead = ListTail = NULL;
		ListCurrent = NULL;
		EntryCount = 0;
	}
};	//CSList


//////////////////////////////////////
// Stack implementation
//////////////////////////////////////
template <class ENTRY_TYPE>
class CStack
{
public:
	CStack()
	{
		ListHead = ListTail = NULL;
		EntryCount = 0;
	}

	virtual ~CStack()
	{
		RemoveAll();
	}

private:
	int EntryCount;
	NTSLIST_ENTRY<ENTRY_TYPE> *ListHead;
	NTSLIST_ENTRY<ENTRY_TYPE> *ListTail;

public:
	// Get entry count
	__inline int GetCount() const
	{
		return EntryCount;
	}

	// Insert to head
	BOOL Push(ENTRY_TYPE *entry)
	{
		NTSLIST_ENTRY<ENTRY_TYPE> *le = new NTSLIST_ENTRY<ENTRY_TYPE>;
		if (!le)
			return FALSE;

		le->Entry = entry;
		le->Next = ListHead;

		ListHead = le;

		if (ListTail == NULL)
			ListTail = le;		// Empty list

		EntryCount ++;
		return TRUE;
	}

	// Remove from head
	ENTRY_TYPE* Pop()
	{
		if (ListHead == NULL)
			return NULL;

		NTSLIST_ENTRY<ENTRY_TYPE> *le = ListHead;
		ENTRY_TYPE *e = le->Entry;

		if (ListTail == ListHead)
			ListTail = ListHead->Next;
		ListHead = ListHead->Next;

		delete le;
		EntryCount --;

		return e;
	}

	// Remove all entries
	void RemoveAll()
	{
		NTSLIST_ENTRY<ENTRY_TYPE> *le;

		while (ListHead)
		{
			le = ListHead->Next;
			delete ListHead->Entry;
			delete ListHead;

			ListHead = le;
		}

		ListHead = ListTail = NULL;
		EntryCount = 0;
	}
};	//CStack

#endif
