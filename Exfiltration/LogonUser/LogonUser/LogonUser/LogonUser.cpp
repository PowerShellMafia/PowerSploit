// LogonUser.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;

size_t wcsByteLen( const wchar_t* str );
void InitUnicodeString( UNICODE_STRING& str, const wchar_t* value, BYTE* buffer, size_t& offset );
PVOID CreateNtlmLogonStructure(wstring domain, wstring username, wstring password, DWORD* size);
size_t WriteUnicodeString(wstring str, UNICODE_STRING* uniStr, PVOID baseAddress, size_t offset);

int _tmain(int argc, _TCHAR* argv[])
{
	//Get a handle to LSA
	HANDLE hLSA = NULL;
	NTSTATUS status = LsaConnectUntrusted(&hLSA);
	if (status != 0)
	{
		cout << "Error calling LsaConnectUntrusted. Error code: " << status << endl;
		return -1;
	}
	if (hLSA == NULL)
	{
		cout << "hLSA is NULL, this shouldn't ever happen" << endl;
		return -1;
	}

	//Build LsaLogonUser parameters
	LSA_STRING originName = {};
	char originNameStr[] = "qpqp";
	originName.Buffer = originNameStr;
	originName.Length = (USHORT)strlen(originNameStr);
	originName.MaximumLength = originName.Length;

	ULONG authPackage = 0;
	PLSA_STRING authPackageName = new LSA_STRING();
	char authPackageBuf[] = MSV1_0_PACKAGE_NAME;
	authPackageName->Buffer = authPackageBuf;
	authPackageName->Length = (USHORT)strlen(authPackageBuf);
	authPackageName->MaximumLength = (USHORT)strlen(authPackageBuf);
	status = LsaLookupAuthenticationPackage(hLSA, authPackageName, &authPackage);
	if (status != 0)
	{
		int winError = LsaNtStatusToWinError(status);
		cout << "Call to LsaLookupAuthenticationPackage failed. Error code: " << winError;
		return -1;
	}

	DWORD authBufferSize = 0;
	PVOID authBuffer = CreateNtlmLogonStructure(L"VMWORKSTATION", L"testuser", L"Password1", &authBufferSize);
		cout << "authBufferSize: " << authBufferSize << endl;

	//Get TokenSource
	HANDLE hProcess = GetCurrentProcess();//todo
	HANDLE procToken = NULL;
	BOOL success = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &procToken);
	if (!success)
	{
		DWORD errorCode = GetLastError();
		cout << "Call to OpenProcessToken failed. Errorcode: " << errorCode << endl;
		return -1;
	}

	TOKEN_SOURCE tokenSource = {};
	DWORD realSize = 0;
	success = GetTokenInformation(procToken, TokenSource, &tokenSource, sizeof(tokenSource), &realSize);
	if (!success)
	{
		cout << "Call to GetTokenInformation failed." << endl;
		return -1;
	}


	//Misc
	PVOID profileBuffer = NULL;
	ULONG profileBufferSize = 0;
	LUID loginId;
	HANDLE token = NULL;
	QUOTA_LIMITS quotaLimits;
	NTSTATUS subStatus = 0;

	status = LsaLogonUser(hLSA, 
		&originName, 
		RemoteInteractive, 
		authPackage, 
		authBuffer,
		authBufferSize, 
		0, 
		&tokenSource, 
		&profileBuffer,
		&profileBufferSize,
		&loginId,
		&token,
		&quotaLimits,
		&subStatus);

	if (status != 0)
	{
		NTSTATUS winError = LsaNtStatusToWinError(status);
		cout << "Error calling LsaLogonUser. Error code: " << winError << endl;
		return -1;
	}

	cout << "Success!" << endl;

	return 1;
}

//size will be set to the size of the structure created
PVOID CreateNtlmLogonStructure(wstring domain, wstring username, wstring password, DWORD* size)
{
	size_t wcharSize = sizeof(wchar_t);

	size_t totalSize = sizeof(MSV1_0_INTERACTIVE_LOGON) + ((domain.length() + username.length() + password.length()) * wcharSize);
	MSV1_0_INTERACTIVE_LOGON* ntlmLogon = (PMSV1_0_INTERACTIVE_LOGON)(new BYTE[totalSize]);
	size_t offset = sizeof(MSV1_0_INTERACTIVE_LOGON);

	ntlmLogon->MessageType = MsV1_0InteractiveLogon;
	offset += WriteUnicodeString(domain, &(ntlmLogon->LogonDomainName), ntlmLogon, offset);
	offset += WriteUnicodeString(username, &(ntlmLogon->UserName), ntlmLogon, offset);
	offset += WriteUnicodeString(password, &(ntlmLogon->Password), ntlmLogon, offset);

	*size = (DWORD)totalSize; //If the size is bigger than a DWORD, there is a gigantic bug somewhere.
	return ntlmLogon;
}

size_t WriteUnicodeString(wstring str, UNICODE_STRING* uniStr, PVOID baseAddress, size_t offset)
{
	const wchar_t* buffer = str.c_str();
	size_t size = str.length() * sizeof(wchar_t);
	uniStr->Length = (USHORT)size;
	uniStr->MaximumLength = (USHORT)size;
	uniStr->Buffer = (PWSTR)((UINT_PTR)baseAddress + offset);
	memcpy((PVOID)((UINT_PTR)baseAddress + offset), str.c_str(), size);
	return size;
}