/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence    : http://creativecommons.org/licenses/by/3.0/fr/
	Ce fichier : http://creativecommons.org/licenses/by/3.0/fr/
*/
#pragma once
#include "globdefs.h"
#include <sspi.h>
#include <wincred.h>

typedef struct _KIWI_GENERIC_PRIMARY_CREDENTIAL
{
	LSA_UNICODE_STRING UserName;
	LSA_UNICODE_STRING Domaine;
	LSA_UNICODE_STRING Password;
} KIWI_GENERIC_PRIMARY_CREDENTIAL, * PKIWI_GENERIC_PRIMARY_CREDENTIAL;

typedef NTSTATUS	(WINAPIV * PLSA_INITIALIZE_PROTECTED_MEMORY) ();

typedef PVOID *PLSA_CLIENT_REQUEST;
typedef LPTHREAD_START_ROUTINE  SEC_THREAD_START;
typedef LPSECURITY_ATTRIBUTES   SEC_ATTRS;

typedef struct _SECPKG_CLIENT_INFO {
    LUID            LogonId;            // Effective Logon Id
    ULONG           ProcessID;          // Process Id of caller
    ULONG           ThreadID;           // Thread Id of caller
    BOOLEAN         HasTcbPrivilege;    // Client has TCB
    BOOLEAN         Impersonating;      // Client is impersonating
    BOOLEAN         Restricted;         // Client is restricted
    // NT 5.1
    UCHAR                           ClientFlags;            // Extra flags about the client
    SECURITY_IMPERSONATION_LEVEL    ImpersonationLevel;     // Impersonation level of client
    // NT 6
    HANDLE                          ClientToken;
} SECPKG_CLIENT_INFO, * PSECPKG_CLIENT_INFO;

typedef enum _LSA_TOKEN_INFORMATION_TYPE {
    LsaTokenInformationNull,  // Implies LSA_TOKEN_INFORMATION_NULL data type
    LsaTokenInformationV1,     // Implies LSA_TOKEN_INFORMATION_V1 data type
    LsaTokenInformationV2     // Implies LSA_TOKEN_INFORMATION_V2 data type
} LSA_TOKEN_INFORMATION_TYPE, *PLSA_TOKEN_INFORMATION_TYPE;

typedef enum _SECPKG_NAME_TYPE {
    SecNameSamCompatible,
    SecNameAlternateId,
    SecNameFlat,
    SecNameDN,
    SecNameSPN
} SECPKG_NAME_TYPE;

typedef struct _SECPKG_CALL_INFO {
    ULONG           ProcessId;
    ULONG           ThreadId;
    ULONG           Attributes;
    ULONG           CallCount;
    PVOID           MechOid; // mechanism objection identifer
} SECPKG_CALL_INFO, * PSECPKG_CALL_INFO;

typedef enum _SECPKG_SESSIONINFO_TYPE {
    SecSessionPrimaryCred       // SessionInformation is SECPKG_PRIMARY_CRED
} SECPKG_SESSIONINFO_TYPE;

typedef struct _SECPKG_PRIMARY_CRED {
    LUID LogonId;
    UNICODE_STRING DownlevelName;   // Sam Account Name
    UNICODE_STRING DomainName;      // Netbios domain name where account is located
    UNICODE_STRING Password;
    UNICODE_STRING OldPassword;
    PSID UserSid;
    ULONG Flags;
    UNICODE_STRING DnsDomainName;   // DNS domain name where account is located (if known)
    UNICODE_STRING Upn;             // UPN of account (if known)
    UNICODE_STRING LogonServer;
    UNICODE_STRING Spare1;
    UNICODE_STRING Spare2;
    UNICODE_STRING Spare3;
    UNICODE_STRING Spare4;
} SECPKG_PRIMARY_CRED, *PSECPKG_PRIMARY_CRED;

typedef struct _SECPKG_SUPPLEMENTAL_CRED {
    UNICODE_STRING PackageName;
    ULONG CredentialSize;
#ifdef MIDL_PASS
    [size_is(CredentialSize)]
#endif // MIDL_PASS
    PUCHAR Credentials;
} SECPKG_SUPPLEMENTAL_CRED, *PSECPKG_SUPPLEMENTAL_CRED;

typedef struct _SECPKG_SUPPLEMENTAL_CRED_ARRAY {
    ULONG CredentialCount;
#ifdef MIDL_PASS
    [size_is(CredentialCount)] SECPKG_SUPPLEMENTAL_CRED Credentials[*];
#else // MIDL_PASS
    SECPKG_SUPPLEMENTAL_CRED Credentials[1];
#endif // MIDL_PASS
} SECPKG_SUPPLEMENTAL_CRED_ARRAY, *PSECPKG_SUPPLEMENTAL_CRED_ARRAY;

typedef NTSTATUS	(WINAPI * PLSA_CALLBACK_FUNCTION)				(ULONG_PTR Argument1, ULONG_PTR Argument2, PSecBuffer InputBuffer, PSecBuffer OutputBuffer);

typedef NTSTATUS	(WINAPI * PLSA_CREATE_LOGON_SESSION)			(IN PLUID LogonId);
typedef NTSTATUS	(WINAPI * PLSA_DELETE_LOGON_SESSION)			(IN PLUID LogonId);
typedef NTSTATUS	(WINAPI * PLSA_ADD_CREDENTIAL)					(IN PLUID LogonId, IN ULONG AuthenticationPackage, IN PLSA_STRING PrimaryKeyValue, IN PLSA_STRING Credentials);
typedef NTSTATUS	(WINAPI * PLSA_GET_CREDENTIALS)					(IN PLUID LogonId, IN ULONG AuthenticationPackage, IN OUT PULONG QueryContext, IN BOOLEAN RetrieveAllCredentials, IN PLSA_STRING PrimaryKeyValue, OUT PULONG PrimaryKeyLength, IN PLSA_STRING Credentials);
typedef NTSTATUS	(WINAPI * PLSA_DELETE_CREDENTIAL)				(IN PLUID LogonId, IN ULONG AuthenticationPackage, IN PLSA_STRING PrimaryKeyValue);
typedef PVOID		(WINAPI * PLSA_ALLOCATE_LSA_HEAP)				(IN ULONG Length);
typedef VOID		(WINAPI * PLSA_FREE_LSA_HEAP)					(IN PVOID Base);
typedef PVOID		(WINAPI * PLSA_ALLOCATE_PRIVATE_HEAP)			(IN SIZE_T Length);
typedef VOID		(WINAPI * PLSA_FREE_PRIVATE_HEAP)				(IN PVOID Base);
typedef NTSTATUS	(WINAPI * PLSA_ALLOCATE_CLIENT_BUFFER)			(IN PLSA_CLIENT_REQUEST ClientRequest, IN ULONG LengthRequired, OUT PVOID *ClientBaseAddress);
typedef NTSTATUS	(WINAPI * PLSA_FREE_CLIENT_BUFFER)				(IN PLSA_CLIENT_REQUEST ClientRequest, IN PVOID ClientBaseAddress);
typedef NTSTATUS	(WINAPI * PLSA_COPY_TO_CLIENT_BUFFER)			(IN PLSA_CLIENT_REQUEST ClientRequest, IN ULONG Length, IN PVOID ClientBaseAddress, IN PVOID BufferToCopy);
typedef NTSTATUS	(WINAPI * PLSA_COPY_FROM_CLIENT_BUFFER)			(IN PLSA_CLIENT_REQUEST ClientRequest, IN ULONG Length, IN PVOID BufferToCopy, IN PVOID ClientBaseAddress);
typedef NTSTATUS	(WINAPI * PLSA_IMPERSONATE_CLIENT)				(VOID);
typedef NTSTATUS	(WINAPI * PLSA_UNLOAD_PACKAGE)					(VOID);
typedef NTSTATUS	(WINAPI * PLSA_DUPLICATE_HANDLE)				(IN HANDLE SourceHandle, OUT PHANDLE DestionationHandle);
typedef NTSTATUS	(WINAPI * PLSA_SAVE_SUPPLEMENTAL_CREDENTIALS)	(IN PLUID LogonId, IN ULONG SupplementalCredSize, IN PVOID SupplementalCreds, IN BOOLEAN Synchronous);
typedef HANDLE		(WINAPI * PLSA_CREATE_THREAD)					(IN SEC_ATTRS SecurityAttributes, IN ULONG StackSize, IN SEC_THREAD_START StartFunction, IN PVOID ThreadParameter, IN ULONG CreationFlags, OUT PULONG ThreadId);
typedef NTSTATUS	(WINAPI * PLSA_GET_CLIENT_INFO)					(OUT PSECPKG_CLIENT_INFO ClientInfo);
typedef HANDLE		(WINAPI * PLSA_REGISTER_NOTIFICATION)			(IN SEC_THREAD_START StartFunction, IN PVOID Parameter, IN ULONG NotificationType, IN ULONG NotificationClass, IN ULONG NotificationFlags, IN ULONG IntervalMinutes, IN OPTIONAL HANDLE WaitEvent);
typedef NTSTATUS	(WINAPI * PLSA_CANCEL_NOTIFICATION)				(IN HANDLE NotifyHandle);
typedef NTSTATUS	(WINAPI * PLSA_MAP_BUFFER)						(IN PSecBuffer InputBuffer, OUT PSecBuffer OutputBuffer);
typedef NTSTATUS	(WINAPI * PLSA_CREATE_TOKEN)					(IN PLUID LogonId, IN PTOKEN_SOURCE TokenSource, IN SECURITY_LOGON_TYPE LogonType, IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, IN LSA_TOKEN_INFORMATION_TYPE TokenInformationType, IN PVOID TokenInformation, IN PTOKEN_GROUPS TokenGroups, IN PUNICODE_STRING AccountName, IN PUNICODE_STRING AuthorityName, IN PUNICODE_STRING Workstation, IN PUNICODE_STRING ProfilePath, OUT PHANDLE Token, OUT PNTSTATUS SubStatus);
typedef NTSTATUS	(WINAPI * PLSA_CREATE_TOKEN_EX)					(IN PLUID LogonId, IN PTOKEN_SOURCE TokenSource, IN SECURITY_LOGON_TYPE LogonType, IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, IN LSA_TOKEN_INFORMATION_TYPE TokenInformationType, IN PVOID TokenInformation, IN PTOKEN_GROUPS TokenGroups, IN PUNICODE_STRING Workstation, IN PUNICODE_STRING ProfilePath, IN PVOID SessionInformation, IN SECPKG_SESSIONINFO_TYPE SessionInformationType, OUT PHANDLE Token, OUT PNTSTATUS SubStatus);
typedef VOID		(WINAPI * PLSA_AUDIT_LOGON)						(IN NTSTATUS Status, IN NTSTATUS SubStatus, IN PUNICODE_STRING AccountName, IN PUNICODE_STRING AuthenticatingAuthority, IN PUNICODE_STRING WorkstationName, IN OPTIONAL PSID UserSid, IN SECURITY_LOGON_TYPE LogonType, IN PTOKEN_SOURCE TokenSource, IN PLUID LogonId);
typedef NTSTATUS	(WINAPI * PLSA_CALL_PACKAGE)					(IN PUNICODE_STRING AuthenticationPackage, IN PVOID ProtocolSubmitBuffer, IN ULONG SubmitBufferLength, OUT PVOID *ProtocolReturnBuffer, OUT PULONG ReturnBufferLength, OUT PNTSTATUS ProtocolStatus);
typedef NTSTATUS	(WINAPI * PLSA_CALL_PACKAGEEX)					(IN PUNICODE_STRING AuthenticationPackage, IN PVOID ClientBufferBase, IN PVOID ProtocolSubmitBuffer, IN ULONG SubmitBufferLength, OUT PVOID *ProtocolReturnBuffer, OUT PULONG ReturnBufferLength, OUT PNTSTATUS ProtocolStatus);
typedef NTSTATUS	(WINAPI * PLSA_CALL_PACKAGE_PASSTHROUGH)		(IN PUNICODE_STRING AuthenticationPackage, IN PVOID ClientBufferBase, IN PVOID ProtocolSubmitBuffer, IN ULONG SubmitBufferLength, OUT PVOID *ProtocolReturnBuffer, OUT PULONG ReturnBufferLength, OUT PNTSTATUS ProtocolStatus);
typedef BOOLEAN		(WINAPI * PLSA_GET_CALL_INFO)					(OUT PSECPKG_CALL_INFO Info);
typedef PVOID		(WINAPI * PLSA_CREATE_SHARED_MEMORY)			(ULONG MaxSize, ULONG InitialSize);
typedef PVOID		(WINAPI * PLSA_ALLOCATE_SHARED_MEMORY)			(PVOID SharedMem, ULONG Size);
typedef VOID		(WINAPI * PLSA_FREE_SHARED_MEMORY)				(PVOID SharedMem, PVOID Memory);
typedef BOOLEAN		(WINAPI * PLSA_DELETE_SHARED_MEMORY)			(PVOID SharedMem);
typedef NTSTATUS	(WINAPI * PLSA_OPEN_SAM_USER)					(PSECURITY_STRING Name, SECPKG_NAME_TYPE NameType, PSECURITY_STRING Prefix, BOOLEAN AllowGuest, ULONG Reserved, PVOID * UserHandle);
typedef NTSTATUS	(WINAPI * PLSA_GET_USER_CREDENTIALS)			(PVOID UserHandle, PVOID * PrimaryCreds, PULONG PrimaryCredsSize, PVOID * SupplementalCreds, PULONG SupplementalCredsSize);
typedef NTSTATUS	(WINAPI * PLSA_GET_USER_AUTH_DATA)				(PVOID UserHandle, PUCHAR * UserAuthData, PULONG UserAuthDataSize);
typedef NTSTATUS	(WINAPI * PLSA_CLOSE_SAM_USER)					(PVOID UserHandle);
typedef NTSTATUS	(WINAPI * PLSA_GET_AUTH_DATA_FOR_USER)			(PSECURITY_STRING Name, SECPKG_NAME_TYPE NameType, PSECURITY_STRING Prefix, PUCHAR * UserAuthData, PULONG UserAuthDataSize, PUNICODE_STRING UserFlatName);
typedef NTSTATUS	(WINAPI * PLSA_CONVERT_AUTH_DATA_TO_TOKEN)		(IN PVOID UserAuthData, IN ULONG UserAuthDataSize, IN SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, IN PTOKEN_SOURCE TokenSource, IN SECURITY_LOGON_TYPE LogonType, IN PUNICODE_STRING AuthorityName, OUT PHANDLE Token, OUT PLUID LogonId, OUT PUNICODE_STRING AccountName, OUT PNTSTATUS SubStatus);
typedef NTSTATUS	(WINAPI * PLSA_CRACK_SINGLE_NAME)				(IN ULONG FormatOffered, IN BOOLEAN PerformAtGC, IN PUNICODE_STRING NameInput, IN PUNICODE_STRING Prefix OPTIONAL, IN ULONG RequestedFormat, OUT PUNICODE_STRING CrackedName, OUT PUNICODE_STRING DnsDomainName, OUT PULONG SubStatus);
typedef NTSTATUS	(WINAPI * PLSA_AUDIT_ACCOUNT_LOGON)				(IN ULONG AuditId, IN BOOLEAN Success, IN PUNICODE_STRING Source, IN PUNICODE_STRING ClientName, IN PUNICODE_STRING MappedName, IN NTSTATUS Status);
typedef NTSTATUS	(WINAPI * PLSA_CLIENT_CALLBACK)					(IN PCHAR Callback, IN ULONG_PTR Argument1, IN ULONG_PTR Argument2, IN PSecBuffer Input, OUT PSecBuffer Output);
typedef NTSTATUS	(WINAPI * PLSA_REGISTER_CALLBACK)				(ULONG CallbackId, PLSA_CALLBACK_FUNCTION Callback);
typedef NTSTATUS	(WINAPI * PLSA_UPDATE_PRIMARY_CREDENTIALS)		(IN PSECPKG_PRIMARY_CRED PrimaryCredentials, IN OPTIONAL PSECPKG_SUPPLEMENTAL_CRED_ARRAY Credentials);
typedef VOID		(WINAPI * PLSA_PROTECT_MEMORY)					(IN PVOID Buffer, IN ULONG BufferSize);
typedef NTSTATUS	(WINAPI * PLSA_OPEN_TOKEN_BY_LOGON_ID)			(IN PLUID LogonId, OUT HANDLE *RetTokenHandle);
typedef NTSTATUS	(WINAPI * PLSA_EXPAND_AUTH_DATA_FOR_DOMAIN)		(IN PUCHAR UserAuthData, IN ULONG UserAuthDataSize, IN PVOID Reserved, OUT PUCHAR * ExpandedAuthData, OUT PULONG ExpandedAuthDataSize);



#ifndef _ENCRYPTED_CREDENTIAL_DEFINED
#define _ENCRYPTED_CREDENTIAL_DEFINED

typedef struct _ENCRYPTED_CREDENTIALW {
    CREDENTIALW Cred;
    ULONG ClearCredentialBlobSize;
} ENCRYPTED_CREDENTIALW, *PENCRYPTED_CREDENTIALW;
#endif // _ENCRYPTED_CREDENTIAL_DEFINED

#define CREDP_FLAGS_IN_PROCESS      0x01    // Caller is in-process. Password data may be returned
#define CREDP_FLAGS_USE_MIDL_HEAP   0x02    // Allocated buffer should use MIDL_user_allocte
#define CREDP_FLAGS_DONT_CACHE_TI   0x04    // TargetInformation shouldn't be cached for CredGetTargetInfo
#define CREDP_FLAGS_CLEAR_PASSWORD  0x08    // Credential blob is passed in in-the-clear
#define CREDP_FLAGS_USER_ENCRYPTED_PASSWORD 0x10    // Credential blob is passed protected by RtlEncryptMemory
#define CREDP_FLAGS_TRUSTED_CALLER 0x20     // Caller is a trusted process (eg. logon process).

typedef enum _CredParsedUserNameType
{
    parsedUsernameInvalid = 0,
    parsedUsernameUpn,
    parsedUsernameNt4Style,
    parsedUsernameCertificate,
    parsedUsernameNonQualified
} CredParsedUserNameType;


typedef NTSTATUS (NTAPI CredReadFn) (IN PLUID LogonId, IN ULONG CredFlags, IN LPWSTR TargetName, IN ULONG Type, IN ULONG Flags, OUT PENCRYPTED_CREDENTIALW *Credential);
typedef NTSTATUS (NTAPI CredReadDomainCredentialsFn) (IN PLUID LogonId, IN ULONG CredFlags, IN PCREDENTIAL_TARGET_INFORMATIONW TargetInfo, IN ULONG Flags, OUT PULONG Count, OUT PENCRYPTED_CREDENTIALW **Credential);

typedef VOID (NTAPI CredFreeCredentialsFn) (IN ULONG Count, IN PENCRYPTED_CREDENTIALW *Credentials OPTIONAL);
typedef NTSTATUS (NTAPI CredWriteFn) (IN PLUID LogonId, IN ULONG CredFlags, IN PENCRYPTED_CREDENTIALW Credential, IN ULONG Flags);
typedef NTSTATUS (NTAPI CrediUnmarshalandDecodeStringFn)(IN  LPWSTR  MarshaledString, OUT LPBYTE  *Blob, OUT ULONG *BlobSize, OUT BOOLEAN *IsFailureFatal);

typedef struct _LSA_SECPKG_FUNCTION_TABLE {
    PLSA_CREATE_LOGON_SESSION CreateLogonSession;
    PLSA_DELETE_LOGON_SESSION DeleteLogonSession;
    PLSA_ADD_CREDENTIAL AddCredential;
    PLSA_GET_CREDENTIALS GetCredentials;
    PLSA_DELETE_CREDENTIAL DeleteCredential;
    PLSA_ALLOCATE_LSA_HEAP AllocateLsaHeap;
    PLSA_FREE_LSA_HEAP FreeLsaHeap;
    PLSA_ALLOCATE_CLIENT_BUFFER AllocateClientBuffer;
    PLSA_FREE_CLIENT_BUFFER FreeClientBuffer;
    PLSA_COPY_TO_CLIENT_BUFFER CopyToClientBuffer;
    PLSA_COPY_FROM_CLIENT_BUFFER CopyFromClientBuffer;
    PLSA_IMPERSONATE_CLIENT ImpersonateClient;
    PLSA_UNLOAD_PACKAGE UnloadPackage;
    PLSA_DUPLICATE_HANDLE DuplicateHandle;
    PLSA_SAVE_SUPPLEMENTAL_CREDENTIALS SaveSupplementalCredentials;
    PLSA_CREATE_THREAD CreateThread;
    PLSA_GET_CLIENT_INFO GetClientInfo;
    PLSA_REGISTER_NOTIFICATION RegisterNotification;
    PLSA_CANCEL_NOTIFICATION CancelNotification;
    PLSA_MAP_BUFFER MapBuffer;
    PLSA_CREATE_TOKEN CreateToken;
    PLSA_AUDIT_LOGON AuditLogon;
    PLSA_CALL_PACKAGE CallPackage;
    PLSA_FREE_LSA_HEAP FreeReturnBuffer;
    PLSA_GET_CALL_INFO GetCallInfo;
    PLSA_CALL_PACKAGEEX CallPackageEx;
    PLSA_CREATE_SHARED_MEMORY CreateSharedMemory;
    PLSA_ALLOCATE_SHARED_MEMORY AllocateSharedMemory;
    PLSA_FREE_SHARED_MEMORY FreeSharedMemory;
    PLSA_DELETE_SHARED_MEMORY DeleteSharedMemory;
    PLSA_OPEN_SAM_USER OpenSamUser;
    PLSA_GET_USER_CREDENTIALS GetUserCredentials;
    PLSA_GET_USER_AUTH_DATA GetUserAuthData;
    PLSA_CLOSE_SAM_USER CloseSamUser;
    PLSA_CONVERT_AUTH_DATA_TO_TOKEN ConvertAuthDataToToken;
    PLSA_CLIENT_CALLBACK ClientCallback;
    PLSA_UPDATE_PRIMARY_CREDENTIALS UpdateCredentials;
    PLSA_GET_AUTH_DATA_FOR_USER GetAuthDataForUser;
    PLSA_CRACK_SINGLE_NAME CrackSingleName;
    PLSA_AUDIT_ACCOUNT_LOGON AuditAccountLogon;
    PLSA_CALL_PACKAGE_PASSTHROUGH CallPackagePassthrough;
    CredReadFn *CrediRead;
    CredReadDomainCredentialsFn *CrediReadDomainCredentials;
    CredFreeCredentialsFn *CrediFreeCredentials;
    PLSA_PROTECT_MEMORY LsaProtectMemory;
    PLSA_PROTECT_MEMORY LsaUnprotectMemory;
    PLSA_OPEN_TOKEN_BY_LOGON_ID OpenTokenByLogonId;
    PLSA_EXPAND_AUTH_DATA_FOR_DOMAIN ExpandAuthDataForDomain;
    PLSA_ALLOCATE_PRIVATE_HEAP AllocatePrivateHeap;
    PLSA_FREE_PRIVATE_HEAP FreePrivateHeap;
    PLSA_CREATE_TOKEN_EX CreateTokenEx;
    CredWriteFn *CrediWrite;
    CrediUnmarshalandDecodeStringFn *CrediUnmarshalandDecodeString;
} LSA_SECPKG_FUNCTION_TABLE, *PLSA_SECPKG_FUNCTION_TABLE;
