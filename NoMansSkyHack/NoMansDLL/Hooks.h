#pragma once
#include <Windows.h>
namespace Hooks {
	class Detour64
	{
	
	private:
		BYTE m_absJmp[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
		BYTE m_relJmp[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
		UINT_PTR m_hookAddress = 0;
		UINT_PTR m_trampolinAddress = 0;
		PBYTE m_byteArrayTrampolin = nullptr;
		UINT m_trampolinRawSize = 0;
		UINT m_trampolinSize = 0;
		UINT m_overridenBytesCount = 0;
		BYTE* m_originalOpcodes = nullptr;
		bool m_in2GbRange = true;
		bool m_bIsHooked = false;

		bool placeRelJmpHook();
		bool placeAbsJmpHook();
		PVOID Allocate2GBRange(UINT_PTR address, SIZE_T dwSize);
	public:
		Detour64();
		Detour64(UINT_PTR HookAt, PBYTE CompiledTrampolin, UINT SizeOfTrampolin, UINT BytesToOverride, bool In2GbRange);
		~Detour64();
		void Setup(UINT_PTR HookAt, PBYTE CompiledTrampolin, UINT SizeOfTrampolin, UINT BytesToOverride, bool In2GbRange);
		bool Hook();
		bool UnHook();
		UINT_PTR GetTrampolinAddress();
		UINT_PTR GetHookAddress();
		UINT GetTrampolinSize();
		UINT GetTramplinRawSize();
		bool isActive();

		
		
	};
	
	bool JmpHook(UINT_PTR HookAt, BYTE* Trampolin, UINT SizeOfTrampolin, UINT BytesToOverride, UINT_PTR* TrampolinAddy);
}

