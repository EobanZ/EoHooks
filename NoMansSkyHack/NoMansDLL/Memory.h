#pragma once
#include <Windows.h>

namespace Mem {
	template<typename T>
	T Read(UINT_PTR address) {
		return *((T*)address);
	}

	template<typename T>
	void Write(UINT_PTR address, T value) {
		*((T*)address) = value;
	}

	template<typename T>
	T* ReadPointer(UINT_PTR address) {
		return ((T*)address);
	}

	template<typename T>
	DWORD protectMemory(UINT_PTR address, DWORD prot) {
		DWORD oldProt;
		VirtualProtect((LPVOID)address, sizeof(T), prot, &oldProt);
		return oldProt;
	}

	template<int SIZE>
	void writeNop(UINT_PTR address)
	{
		auto oldProtection = Memory::protectMemory<BYTE[SIZE]>(address, PAGE_EXECUTE_READWRITE);
		for (int i = 0; i < SIZE; i++)
		{
			Memory::Write<BYTE>(address + i, 0x90);
		}
		Memory::protectMemory<BYTE[SIZE]>(address, oldProtection);
	}
}

