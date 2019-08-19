#include "Hooks.h"
#include "Memory.h"
#include <stdio.h>
#include <stdint.h>
namespace Hooks {

	PVOID Allocate2GBRange(UINT_PTR address, SIZE_T dwSize)
	{
		static ULONG dwAllocationGranularity;

		if (!dwAllocationGranularity)
		{
			SYSTEM_INFO si;
			GetSystemInfo(&si);
			dwAllocationGranularity = si.dwAllocationGranularity;
		}

		UINT_PTR min, max, addr, add = dwAllocationGranularity - 1, mask = ~add;

		min = address >= 0x80000000 ? (address - 0x80000000 + add) & mask : 0;
		max = address < (UINTPTR_MAX - 0x80000000) ? (address + 0x80000000) & mask : UINTPTR_MAX;

		::MEMORY_BASIC_INFORMATION mbi;
		do
		{
			if (!VirtualQuery((void*)min, &mbi, sizeof(mbi))) return NULL;

			min = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;

			if (mbi.State == MEM_FREE)
			{
				addr = ((UINT_PTR)mbi.BaseAddress + add) & mask;

				if (addr < min && dwSize <= (min - addr))
				{
					if (addr = (UINT_PTR)VirtualAlloc((PVOID)addr, dwSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))
						return (PVOID)addr;
				}
			}


		} while (min < max);

		return NULL;
	}
	
	//AssemblyCaveNearHookAt has to be in 2GB range of HookAt and contain an empty JMP 0x0000 at its end
	//This function places the return jump directly in the codecave
	bool JmpHook(UINT_PTR HookAt, BYTE* TrampolinAssemblies, UINT SizeOfTrampolin, UINT BytesToOverride, UINT_PTR* TrampolinAddy)
	{
		*TrampolinAddy = 0;

		UINT_PTR AssemblyCaveNearHookAt = reinterpret_cast<UINT_PTR>(Allocate2GBRange(HookAt, SizeOfTrampolin));
		if (AssemblyCaveNearHookAt == NULL)
		{
			printf_s("No free memory in 2gb range for rel jmp");
			return false;
		}
		*TrampolinAddy = AssemblyCaveNearHookAt;

		if (*reinterpret_cast<PBYTE>((TrampolinAssemblies + (SizeOfTrampolin - 5))) != 0xE9)
		{
			MessageBoxA(0, "No Jmp to Original Instruction in Assembly Trampolin found", "JmpHook Error", MB_OK);
			return false;
		}

		//Write AssemblyCave into TrampolinAddress
		memcpy(reinterpret_cast<PVOID>(AssemblyCaveNearHookAt), TrampolinAssemblies, SizeOfTrampolin);

		//Place the hook in the SourceCode
		DWORD newOffset = AssemblyCaveNearHookAt - HookAt - 5;

		auto oldProtection = Mem::protectMemory<BYTE[12]>(HookAt, PAGE_EXECUTE_READWRITE);
		*((BYTE*)HookAt) = 0xE9;
		memcpy(reinterpret_cast<PVOID>(HookAt + 1), &newOffset, sizeof(DWORD));
		for (unsigned int i = 5; i < BytesToOverride; i++)
			*((BYTE*)HookAt + i) = 0x90;
		Mem::protectMemory<BYTE[12]>(HookAt, oldProtection);

		//Write the rel JMP address into the skeleton
		DWORD OffsetBackToOriginal;
		DWORD Original = HookAt + 5;
		OffsetBackToOriginal = Original - (AssemblyCaveNearHookAt + SizeOfTrampolin);
		memcpy(reinterpret_cast<PVOID>(AssemblyCaveNearHookAt + (SizeOfTrampolin - 4)), &OffsetBackToOriginal, sizeof(DWORD));

		return true;


	}
}