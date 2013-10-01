/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : http://creativecommons.org/licenses/by/3.0/fr/
*/
#include "mod_thread.h"

bool mod_thread::getList(vector<THREADENTRY32> * monVecteurThreads, DWORD * processId)
{
	bool reussite = false;
	
	HANDLE hThreadsSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if(hThreadsSnapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 monThread;
		monThread.dwSize = sizeof(THREADENTRY32);

		if(reussite = (Thread32First(hThreadsSnapshot, &monThread) != 0))
		{
			do
			{
				if(!processId || (*processId == monThread.th32OwnerProcessID))
					monVecteurThreads->push_back(monThread);
			} while(Thread32Next(hThreadsSnapshot, &monThread));
		}
		CloseHandle(hThreadsSnapshot);
	}

	return reussite;
}

bool mod_thread::suspend(DWORD & threadId)
{
	bool reussite = false;

	HANDLE monHandle = OpenThread(THREAD_SUSPEND_RESUME, false, threadId);
	if(reussite = (monHandle && monHandle != INVALID_HANDLE_VALUE))
	{
		SuspendThread(monHandle);
		CloseHandle(monHandle);
	}

	return reussite;
}

bool mod_thread::resume(DWORD & threadId)
{
	bool reussite = false;

	HANDLE monHandle = OpenThread(THREAD_SUSPEND_RESUME, false, threadId);
	if(reussite = (monHandle && monHandle != INVALID_HANDLE_VALUE))
	{
		ResumeThread(monHandle);
		CloseHandle(monHandle);
	}

	return reussite;
}

bool mod_thread::stop(DWORD & threadId, DWORD exitCode)
{
	bool reussite = false;

	HANDLE monHandle = OpenThread(THREAD_TERMINATE, false, threadId);
	if(reussite = (monHandle && monHandle != INVALID_HANDLE_VALUE))
	{
		TerminateThread(monHandle, exitCode);
		CloseHandle(monHandle);
	}

	return reussite;
}

bool mod_thread::quit(DWORD & threadId)
{
	return PostThreadMessage(threadId, WM_QUIT, NULL, NULL) != 0;
}
