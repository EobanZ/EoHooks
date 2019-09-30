#pragma once
#include <Windows.h>
namespace Hooks {
	class IHook {
	public:
		virtual bool Hook() = 0;
		virtual bool UnHook() = 0;
	};

	//Usefull for inserting own assembly code somewhere in the sourc code
	class Midfunction64 : public IHook
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
		Midfunction64();
		Midfunction64(UINT_PTR HookAt, PBYTE CompiledTrampolin, UINT SizeOfTrampolin, UINT BytesToOverride, bool In2GbRange);
		~Midfunction64();
		void Setup(UINT_PTR HookAt, PBYTE CompiledTrampolin, UINT SizeOfTrampolin, UINT BytesToOverride, bool In2GbRange);
		bool Hook();
		bool UnHook();
		UINT_PTR GetTrampolinAddress();
		UINT_PTR GetHookAddress();
		UINT GetTrampolinSize();
		UINT GetTramplinRawSize();
		bool isActive();



	};

	//Only for hooking functions in prologe. First try to create trampolin in 2gb range then abs. Store address above the prologe to safe space
	class Detour64 : public IHook
	{
	private:
	public:
		Detour64();
		~Detour64();
		void Setup();
		bool Hook();
		bool UnHook();
	};


}

