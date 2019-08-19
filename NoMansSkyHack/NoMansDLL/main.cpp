#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#include "CSignatureScanner.h"
#include "Utils.h"
#include "Memory.h"
#include "Hooks.h"
#include <iostream>


//TODO: Hook als Objekte damit leichtes unhooken möglich ist
UINT_PTR BaseAddress;
UINT_PTR MultiPlierAddress;
CSignatureScanner SigScanner;
bool CollectMulitipier(DWORD multiplier, bool activate)
{
	
	static bool hookActive = false;

	UINT_PTR Offset = 0x469BCB;
	UINT_PTR TrampolinAddress = 0;

	static BYTE cave[]{
		0xBE, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x8D, 0x53, 0x18,
		0x49, 0x8B, 0xCB,
		0xE9, 0x00, 0x00, 0x00, 0x00 //Richtige Addresse zum zurückkehen hier rein
	};

	if (!hookActive)
	{
		memcpy(&cave[1], &multiplier, sizeof(DWORD));
		Hooks::JmpHook(BaseAddress + Offset, cave, sizeof(cave), 7, &TrampolinAddress);
	}
	else
	{
		PBYTE Tramp = reinterpret_cast<PBYTE>(TrampolinAddress);
		if(Tramp)
			memcpy(&Tramp[1], &multiplier, sizeof(DWORD));
	}


	

	return true;
}

HANDLE hMainThread = INVALID_HANDLE_VALUE;
DWORD TidMainThread = 0;
DWORD WINAPI MainThread()
{
	//TODO: Only Scann the .text section!!
	//SYSTEM_INFO sysinfo{ 0 };
	//GetSystemInfo(&sysinfo);
	//char* add = SigScanner.PatternScanInt((char*)sysinfo.lpMinimumApplicationAddress, (UINT_PTR)sysinfo.lpMaximumApplicationAddress -(UINT_PTR)sysinfo.lpMinimumApplicationAddress,Signature("\x48\x8D\x53\x18\x49\x8B\xCB\xE8\x00\x00\x00\x00\x48\x85\xC0\x74\x08\x01\x70\x18\xE9\x00\x00\x00\x00\x48\x63\x4B\x18\x4C\x8B\x4D\x5F\x85\xC9", "xxxxxxxx????xxxxxxxxx????xxxxxxxxxx"));

	//Get Base Address
	HMODULE hMod = GetModuleHandle(NULL);
	BaseAddress = (UINT_PTR)hMod;
	CloseHandle(hMod);

	int collectmultiplier = 1;
	static int lastMult = collectmultiplier;

	while (true)
	{
	
		if (GetAsyncKeyState(VK_OEM_PLUS) & 1)
		{
			collectmultiplier *= 2;
		}
		if (GetAsyncKeyState(VK_OEM_MINUS) & 1)
		{
			collectmultiplier /= 2;
			if (collectmultiplier < 1)
				collectmultiplier = 1;
		}

		if (collectmultiplier != lastMult)
		{
			lastMult = collectmultiplier;
			CollectMulitipier(collectmultiplier, true);
		}
		
	

	}
	
	
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