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

	bool Detour64::placeRelJmpHook()
	{
		PVOID caveAddress = Detour64::Allocate2GBRange(m_hookAddress, (SIZE_T)m_trampolinRawSize + sizeof(m_relJmp));
		if (caveAddress == NULL)
			return false;
		
		m_trampolinAddress = reinterpret_cast<UINT_PTR>(caveAddress);
		m_trampolinSize = m_trampolinRawSize + 5;
		
		//Write AssemblyCave into TrampolinAddress
		memcpy(reinterpret_cast<PVOID>(caveAddress), m_byteArrayTrampolin, m_trampolinRawSize);
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

	bool Detour64::placeAbsJmpHook()
	{
		return false;
	}

	PVOID Detour64::Allocate2GBRange(UINT_PTR address, SIZE_T dwSize)
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

	Detour64::Detour64()
	{
	}

	Detour64::Detour64(UINT_PTR HookAt, PBYTE CompiledTrampolin, UINT SizeOfTrampolin, UINT BytesToOverride, bool In2GbRange)
	{
		Setup(HookAt, CompiledTrampolin, SizeOfTrampolin, BytesToOverride, In2GbRange);
	}

	Detour64::~Detour64()
	{
		if (m_originalOpcodes != nullptr)
			delete[] m_originalOpcodes;
	}

	void Detour64::Setup(UINT_PTR HookAt, PBYTE CompiledTrampolin, UINT SizeOfTrampolin, UINT BytesToOverride, bool In2GbRange)
	{
		m_hookAddress = HookAt;
		m_byteArrayTrampolin = CompiledTrampolin;
		m_trampolinRawSize = SizeOfTrampolin;
		m_overridenBytesCount = BytesToOverride;
		m_bIsHooked = false;
		m_in2GbRange = In2GbRange;
	}

	bool Detour64::Hook()
	{
		if (m_bIsHooked)
			return false;

		//Check if enough bytes for jump
		if (m_in2GbRange && ((m_overridenBytesCount < 5) || (m_byteArrayTrampolin[0] != 0xBE)))
			return false;
		if (!m_in2GbRange && ((m_overridenBytesCount < 6) || (m_byteArrayTrampolin[0] != 0xFF) || (m_byteArrayTrampolin[1] != 0x25)))
			return false;

		if (m_in2GbRange)
			return placeRelJmpHook();
		if (!m_in2GbRange)
			return placeAbsJmpHook();
	}

	bool Detour64::UnHook()
	{
		if (!m_bIsHooked)
			return false;

		//Recreate Original State
		auto oldProtection = Mem::protectMemory<BYTE[12]>(m_hookAddress, PAGE_EXECUTE_READWRITE);
		memcpy(reinterpret_cast<PVOID>(m_hookAddress), m_originalOpcodes, m_overridenBytesCount);
		Mem::protectMemory<BYTE[12]>(m_hookAddress, oldProtection);
		delete[] m_originalOpcodes;
		m_originalOpcodes = nullptr;

		//Free Allocated Memory
		if(m_trampolinAddress != 0)
			VirtualFree(reinterpret_cast<PVOID>(m_trampolinAddress), 0, MEM_RELEASE);
		m_trampolinAddress = 0;
		m_bIsHooked = false;

		return false;
	}

	UINT_PTR Detour64::GetTrampolinAddress()
	{
		if (m_bIsHooked == true)
			return m_trampolinAddress;
		else
			return 0;
	}

	UINT_PTR Detour64::GetHookAddress()
	{
		return m_hookAddress;
	}

	UINT Detour64::GetTrampolinSize()
	{
		if (m_bIsHooked == true)
			return m_trampolinSize;
		else
			return 0;
	}

	UINT Detour64::GetTramplinRawSize()
	{
		return m_trampolinRawSize;
	}

	bool Detour64::isActive()
	{
		return m_bIsHooked;
	}

}