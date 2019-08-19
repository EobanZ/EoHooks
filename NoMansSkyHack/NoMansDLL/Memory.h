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


}

