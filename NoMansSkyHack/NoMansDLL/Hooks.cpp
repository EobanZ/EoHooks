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

	bool Midfunction64::placeRelJmpHook()
	{
		PVOID caveAddress = Midfunction64::Allocate2GBRange(m_hookAddress, (SIZE_T)m_trampolinRawSize + sizeof(m_relJmp));
		if (caveAddress == NULL)
			return false;
		
		m_trampolinAddress = reinterpret_cast<UINT_PTR>(caveAddress);
		m_trampolinSize = m_trampolinRawSize + 5;
		
		//Write AssemblyCave into TrampolinAddress
		memcpy(reinterpret_cast<PVOID>(m_trampolinAddress), m_byteArrayTrampolin, m_trampolinRawSize);
		//Add the Assembly to jump back
		memcpy(reinterpret_cast<PVOID>(m_trampolinAddress + m_trampolinRawSize), m_relJmp ,sizeof(m_relJmp));

		//Fill the Trampolin
		DWORD OffsetBackToOriginal = (m_hookAddress + 5) - (m_trampolinAddress + m_trampolinSize);
		memcpy(reinterpret_cast<PVOID>(m_trampolinAddress + (m_trampolinSize - 4)), &OffsetBackToOriginal, sizeof(DWORD));

		//Save Original Bytes
		m_originalOpcodes = new BYTE[m_overridenBytesCount];
		memcpy(m_originalOpcodes, reinterpret_cast<PVOID>(m_hookAddress), m_overridenBytesCount);

		//Place the Hook
		DWORD newOffset = m_trampolinAddress - m_hookAddress - 5;
		auto oldProtection = Mem::protectMemory<BYTE[12]>(m_hookAddress, PAGE_EXECUTE_READWRITE);
		Mem::Write<BYTE>(m_hookAddress, 0xE9);
		Mem::Write<DWORD>(m_hookAddress + 1, newOffset);
		for (size_t i = 5; i < m_overridenBytesCount; i++)
		{
			Mem::Write<BYTE>(m_hookAddress + i, 0x90);
		}
		Mem::protectMemory<BYTE[12]>(m_hookAddress, oldProtection);

		m_bIsHooked = true;
		return true;
	}

	bool Midfunction64::placeAbsJmpHook()
	{
		PVOID caveAddress = VirtualAlloc(NULL, m_trampolinSize + sizeof(m_absJmp) + sizeof(UINT_PTR), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (caveAddress == NULL)
		{
			m_trampolinSize = 0;
			return false;
		}
		//rawsize + BackJumpOpcodes + absolutaddressBackjump
		m_trampolinAddress = reinterpret_cast<INT_PTR>(caveAddress);
		m_trampolinSize = m_trampolinRawSize + sizeof(m_absJmp) + sizeof(UINT_PTR);
		
		//Write AssemblyCave into TrampolinAddress
		memcpy(reinterpret_cast<PVOID>(m_trampolinAddress), m_byteArrayTrampolin, m_trampolinRawSize);

		//Add the Assembly to jump back
		memcpy(reinterpret_cast<PVOID>(m_trampolinAddress + m_trampolinRawSize), m_absJmp, sizeof(m_absJmp));

		//Fill the Trampolin with return address [if jmp address is 0, it uses whats in the following address]
		UINT_PTR absReturnAddress = m_hookAddress + sizeof(m_absJmp) + sizeof(UINT_PTR);
		Mem::Write<UINT_PTR>(m_trampolinAddress + m_trampolinSize - sizeof(UINT_PTR), absReturnAddress);

		//Save original Bytes
		m_originalOpcodes = new BYTE[m_overridenBytesCount];
		memcpy(m_originalOpcodes, reinterpret_cast<PVOID>(m_hookAddress), m_overridenBytesCount);

		//Place the hook,
		auto oldProtection = Mem::protectMemory<BYTE[20]>(m_hookAddress, PAGE_EXECUTE_READWRITE);
		Mem::Write<BYTE>(m_hookAddress, 0xFF);
		Mem::Write<BYTE>(m_hookAddress + 1, 0x25);
		Mem::Write<DWORD>(m_hookAddress + 2, (DWORD)0);
		Mem::Write<UINT_PTR>(m_hookAddress + sizeof(m_absJmp), m_trampolinAddress);
		for (size_t i = 14; i < m_overridenBytesCount; i++)
		{
			Mem::Write<BYTE>(m_hookAddress + i, 0x90);
		}
		Mem::protectMemory<BYTE[20]>(m_hookAddress, oldProtection);

		m_bIsHooked = true;
		return true;
	}

	PVOID Midfunction64::Allocate2GBRange(UINT_PTR address, SIZE_T dwSize)
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

	Midfunction64::Midfunction64()
	{
	}

	Midfunction64::Midfunction64(UINT_PTR HookAt, PBYTE CompiledTrampolin, UINT SizeOfTrampolin, UINT BytesToOverride, bool In2GbRange)
	{
		Setup(HookAt, CompiledTrampolin, SizeOfTrampolin, BytesToOverride, In2GbRange);
	}

	Midfunction64::~Midfunction64()
	{
		if (m_originalOpcodes != nullptr)
			delete[] m_originalOpcodes;
	}

	void Midfunction64::Setup(UINT_PTR HookAt, PBYTE CompiledTrampolin, UINT SizeOfTrampolin, UINT BytesToOverride, bool In2GbRange)
	{
		m_hookAddress = HookAt;
		m_byteArrayTrampolin = CompiledTrampolin;
		m_trampolinRawSize = SizeOfTrampolin;
		m_overridenBytesCount = BytesToOverride;
		m_bIsHooked = false;
		m_in2GbRange = In2GbRange;
	}

	//Rel Jumps need min 5 bytes
	//Abs jumps need min 14 bytes
	//No instructions whit adresses should be overwriten (jmp, call...)
	bool Midfunction64::Hook()
	{
		if (m_bIsHooked)
			return false;

		//Check if enough bytes for jump
		if (m_in2GbRange && (m_overridenBytesCount < 5))
			return false;
		if (!m_in2GbRange && (m_overridenBytesCount < 14))
			return false;

		if (m_in2GbRange)
			return placeRelJmpHook();
		if (!m_in2GbRange)
			return placeAbsJmpHook();
	}

	bool Midfunction64::UnHook()
	{
		if (!m_bIsHooked)
			return false;
		
		//Recreate Original State
		auto oldProtection = Mem::protectMemory<BYTE[20]>(m_hookAddress, PAGE_EXECUTE_READWRITE);
		memcpy(reinterpret_cast<PVOID>(m_hookAddress), m_originalOpcodes, m_overridenBytesCount);
		Mem::protectMemory<BYTE[20]>(m_hookAddress, oldProtection);
		delete[] m_originalOpcodes;
		m_originalOpcodes = nullptr;

		//Free Allocated Memory
		if(m_trampolinAddress != 0)
			VirtualFree(reinterpret_cast<PVOID>(m_trampolinAddress), 0, MEM_RELEASE);
		m_trampolinAddress = 0;
		m_bIsHooked = false;

		return false;
	}

	UINT_PTR Midfunction64::GetTrampolinAddress()
	{
		if (m_bIsHooked == true)
			return m_trampolinAddress;
		else
			return 0;
	}

	UINT_PTR Midfunction64::GetHookAddress()
	{
		return m_hookAddress;
	}

	UINT Midfunction64::GetTrampolinSize()
	{
		if (m_bIsHooked == true)
			return m_trampolinSize;
		else
			return 0;
	}

	UINT Midfunction64::GetTramplinRawSize()
	{
		return m_trampolinRawSize;
	}

	bool Midfunction64::isActive()
	{
		return m_bIsHooked;
	}

	Detour64::Detour64()
	{
	}

	Detour64::Detour64(UINT_PTR HookAt, UINT_PTR HookFunc, UINT BytesToOverride, bool useAbsJmpInProloge)
	{
		this->Setup(HookAt, HookFunc, BytesToOverride, useAbsJmpInProloge);
	}

	Detour64::~Detour64()
	{
		if (m_originalOpcodes != nullptr)
			delete[] m_originalOpcodes;
	}

	void Detour64::Setup(UINT_PTR HookAt, UINT_PTR HookFunc, UINT BytesToOverride, bool useAbsJmpInProloge = false)
	{
		m_oFuctionAddress = HookAt;
		m_hFuctionAddress = HookFunc;
		m_overridenBytesCount = BytesToOverride;
		m_useAbsJmpInProloge = useAbsJmpInProloge;
	}

	bool Detour64::Hook()
	{
		bool success = false;
		if (m_useAbsJmpInProloge)
			success = TryHookWithAbsJmpInProloge();
		else
			success = TryHookWithTrampolin();
		m_bIsHooked = success;
		return success;
	}

	bool Detour64::TryHookWithTrampolin()
	{
		if (m_overridenBytesCount < 5)
		{
			Error("Not enough bytes for a rel jump");
			return false;
		}



		PVOID trampolinAddress = this->AllocateIn2GBRange(m_oFuctionAddress, 14); //14 size needed to do an absolute jump. instructions + address
		if (trampolinAddress == NULL)
		{
			Error("Could not find memory to allocate near oFunction. TryHookWithAbsJmpInProloge()");
			return false;
		}

		//Fill the Trampolin with jump instructions and address to jump to
		m_trampolinAddress = reinterpret_cast<UINT_PTR>(trampolinAddress);
		memcpy(reinterpret_cast<PVOID>(m_trampolinAddress), m_absJmp, sizeof(m_absJmp)); //Create instruction for an absulute jmp in trampolin
		memcpy(reinterpret_cast<PVOID>(m_trampolinAddress + sizeof(m_absJmp)), reinterpret_cast<PVOID>(m_hFuctionAddress), sizeof(UINT_PTR)); //Copy abs address of hook function where to jump from trampolin

		//Save Original Opcode Bytes
		m_originalOpcodes = new BYTE[m_overridenBytesCount];
		memcpy(m_originalOpcodes, reinterpret_cast<PVOID>(m_oFuctionAddress), m_overridenBytesCount);

		//Create the Gateway. Call this gateway as original fuction after the hook functions ended
		PVOID Gateway = VirtualAlloc(0, m_overridenBytesCount + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (Gateway == NULL)
			return false;
		m_gatewayAddress = reinterpret_cast<UINT_PTR>(Gateway);
		memcpy(Gateway, m_originalOpcodes, m_overridenBytesCount); //Write the stolen opcodes into the gateway
		UINT_PTR returnAddress = m_oFuctionAddress + 5; //The Gateway needs to know where to jump back in the original function: right after the jump we placed
		memcpy(reinterpret_cast<PVOID>(m_gatewayAddress + m_overridenBytesCount), m_absJmp, sizeof(m_absJmp)); //Copy abs jmp instructions after the stolen byte opcodes
		memcpy(reinterpret_cast<PVOID>(m_gatewayAddress + m_overridenBytesCount + sizeof(m_absJmp)), &returnAddress, sizeof(UINT_PTR)); //Adding the adress to jump back to the original function from gateway

		//Place the hook
		DWORD dwOld = 0;
		VirtualProtect(reinterpret_cast<PVOID>(m_oFuctionAddress), m_overridenBytesCount, PAGE_EXECUTE_READWRITE, &dwOld);

		DWORD newOffset = m_trampolinAddress - m_oFuctionAddress - 5;
		*((BYTE*)m_oFuctionAddress) = 0xE9; //JMP
		*((BYTE*)m_oFuctionAddress + 1) = newOffset; 
		for (size_t i = 5; i < m_overridenBytesCount; i++)
		{
			*((BYTE*)m_oFuctionAddress + i) = 0x90;
		}

		VirtualProtect(reinterpret_cast<PVOID>(m_oFuctionAddress), m_overridenBytesCount, dwOld, NULL);

		
		return true;


		
	}

	bool Detour64::TryHookWithAbsJmpInProloge()
	{
		
		return false;
	}

	PVOID Detour64::AllocateIn2GBRange(UINT_PTR address, SIZE_T dwSize)
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

}