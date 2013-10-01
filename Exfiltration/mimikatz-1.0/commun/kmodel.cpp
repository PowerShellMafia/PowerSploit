/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "kmodel.h"

HMODULE g_hModule = NULL;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		g_hModule = hModule;

		HANDLE hThread = CreateThread(NULL,	0, &ThreadProc,	NULL, 0, NULL);
		if(hThread && hThread != INVALID_HANDLE_VALUE)
		{
			return CloseHandle(hThread);
		}
	}
	return TRUE;
}

DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	mod_pipe * monCommunicator = new mod_pipe(L"kiwi\\mimikatz");
	
	bool succes = false;
	for(DWORD nbRetry = 1; nbRetry <= 5 && !succes; nbRetry++)
	{
		succes = monCommunicator->createClient();
		if(!succes)
		{
			Sleep(3000);
		}
	}

	if(succes)
	{
		ptrFunctionString maFonctionString = reinterpret_cast<ptrFunctionString>(GetProcAddress(g_hModule, "getDescription"));
		
		wstring monBuffer = L"Bienvenue dans un processus distant\n\t\t\tGentil Kiwi";
		if(maFonctionString)
		{
			wstring * maDescription = new wstring();
			if(maFonctionString(maDescription))
			{
				monBuffer.append(L"\n\n");
				monBuffer.append(*maDescription);
			}
			delete maDescription;
		}


		
		if(monCommunicator->writeToPipe(monBuffer))
		{				
			for(;;)
			{ 
				if(monCommunicator->readFromPipe(monBuffer))
				{
					wstring fonction = monBuffer;
					vector<wstring> arguments;
		
					size_t monIndex = fonction.find(L' ');
	
					if(monIndex != wstring::npos)
					{
						arguments = mod_parseur::parse(fonction.substr(monIndex + 1));
						fonction = fonction.substr(0, monIndex);
					}

					string procDll(fonction.begin(), fonction.end());
					
					ptrFunction maFonction = reinterpret_cast<ptrFunction>(GetProcAddress(g_hModule, procDll.c_str()));

					if(maFonction)
					{
						if(maFonction(monCommunicator, &arguments))
						{
							monBuffer = L"@";
						}
						else // La fonction à retourné FALSE, il y a donc anomalie bloquante sur le canal
						{
							break;
						}
					}
					else
					{
						monBuffer = L"@Méthode \'";
						monBuffer.append(fonction);
						monBuffer.append(L"\' introuvable !\n");
					}

					if(!monCommunicator->writeToPipe(monBuffer))
					{
						break;
					}
				}
				else
				{
					break;
				}
			}
		}
	}

	delete monCommunicator;

	FreeLibraryAndExitThread(g_hModule, 0);
	return 0;
}

bool sendTo(mod_pipe * monPipe, wstring message)
{
	wstring reponse = L"#";
	reponse.append(message);

	return monPipe->writeToPipe(reponse);
}


__kextdll bool __cdecl ping(mod_pipe * monPipe, vector<wstring> * mesArguments)
{
	bool sendOk = sendTo(monPipe, L"pong");
	
	for(vector<wstring>::iterator monArgument = mesArguments->begin(); monArgument != mesArguments->end() && sendOk; monArgument++)
	{
		wstring maReponse = L" - argument:";
		maReponse.append(*monArgument);
		sendOk = sendTo(monPipe, maReponse);
	}
	
	if(sendOk)
		sendOk = sendTo(monPipe, L"\n");
	
	return sendOk;
}