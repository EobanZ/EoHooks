#include <windows.h>
#include <Psapi.h>
#include <stdio.h>
#include "CSignatureScanner.h"
#include "Utils.h"
#include "Memory.h"
#include "Hooks.h"
#include <iostream>
#include <vector>

std::vector<Hooks::IHook*> vHooks;
UINT_PTR BaseAddress;
CSignatureScanner SigScanner;
Hooks::Midfunction64 jmpHook;
Hooks::Midfunction64 jmpHookAbs;

Hooks::Detour64 detRel;
Hooks::Detour64 detAbs;

typedef int(__stdcall* detFuc)(int arg1, int arg2); //this should be the correct function prototype u want to hook
detFuc orgiFuncRel = 0;
detFuc orgiFuncAbs = 0;

int __stdcall myFunc1(int one, int two)
{
	//bla
	orgiFuncRel(one, two);
}

int __stdcall myFunc2(int one, int two)
{

	orgiFuncAbs(one, two);
}

bool SetupRelJmpTest()
{
	UINT_PTR Offset = 0x46A36B; //Needs to be updated after a new game patch. (Or use SigScanner)

	static BYTE cave[]{
		0xBE, 0x00, 0x00, 0x00, 0x00,
		0x48, 0x8D, 0x53, 0x18,
		0x49, 0x8B, 0xCB,
	};

	jmpHook.Setup(BaseAddress + Offset, cave, sizeof(cave), 7, true);
	vHooks.push_back(&jmpHook);

	return true;
}

bool SetupAbsJmpTest()
{
	UINT_PTR Offset = 0x42E700;

	static BYTE cave2[]{
		0xBE, 0x00, 0x00, 0x00, 0x00,
		0x40, 0x53,
		0x48, 0x83, 0xEC, 0x20,
		0x48, 0x8B, 0x59, 0x48,
		0x4C, 0x8B, 0x41, 0x50
	};
	jmpHookAbs.Setup(BaseAddress + Offset, cave2, sizeof(cave2), 14, false);
	vHooks.push_back(&jmpHookAbs);
	return true;
}

bool SetupDetourTest()
{
	detRel.Setup(0xDEADBEEF, reinterpret_cast<UINT_PTR>(&myFunc1), 6);
	detRel.Hook();
	orgiFuncRel = (detFuc)detRel.GetGatewayAddress();
	vHooks.push_back(&detRel);

	detAbs.Setup(0xBEEFDEAD, (UINT_PTR)myFunc2, 16, true);
	detAbs.Hook();
	orgiFuncAbs = (detFuc)detAbs.GetGatewayAddress();
	vHooks.push_back(&detAbs);


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

	int collectmultiplier = 1; //
	static int lastMult = collectmultiplier;

	SetupRelJmpTest();
	SetupAbsJmpTest();

	while (true)
	{
	
		if (GetAsyncKeyState(VK_F1) & 1)
		{
			if (!jmpHook.isActive())
			{
				if (jmpHook.Hook())
				{
					DWORD multiplier = 10; //When collecting recources in NoMansSky the amount will be multiplied with this. For example: When you collect 2 Carbon you will get 2*multiplier (20)
					UINT_PTR addr = jmpHook.GetTrampolinAddress();
					if(addr != 0)
						Mem::Write<DWORD>(addr+ 1, multiplier);
				}
					
			}
			else
			{
				jmpHook.UnHook();
			}
		}

		if (GetAsyncKeyState(VK_F2) & 1)
		{
			if (!jmpHookAbs.isActive())
			{
				if (jmpHookAbs.Hook())
				{
					DWORD multiplier = 10;
					UINT_PTR addr = jmpHookAbs.GetTrampolinAddress();
					if (addr != 0)
						Mem::Write<DWORD>(addr + 1, multiplier);
				}

			}
			else
			{
				jmpHookAbs.UnHook();
			}
		}
		
		//Unhook everything
		if (GetAsyncKeyState(VK_F12) & 1)
		{
			for (auto var : vHooks)
			{
				var->UnHook();
			}
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