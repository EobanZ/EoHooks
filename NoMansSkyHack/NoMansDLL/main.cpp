#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#include "CSignatureScanner.h"
#include "Utils.h"



HANDLE hMainThread = INVALID_HANDLE_VALUE;
DWORD TidMainThread = 0;
DWORD WINAPI MainThread()
{
	CSignatureScanner SigScanner;

	//Get Base Address
	HMODULE hMod = GetModuleHandle(NULL);
	UINT_PTR BaseAddress = (UINT_PTR)hMod;
	CloseHandle(hMod);



	//TODO: Enable different Collect Rates via jmp or call Hook
	//Mit IDA die funktion analisieren. Vll kann man parameter änder

	while (1) Sleep(100);
	
	return 0;
}



BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hMainThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MainThread, NULL, 0, &TidMainThread);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}