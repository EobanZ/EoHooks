#pragma once
#include <Windows.h>
namespace Hooks {

	static void Error(LPCSTR message)
	{
		MessageBox(NULL, message, "Hooking Error", MB_OK);
	}

	class IHook {
	public:
		virtual bool Hook() = 0;
		virtual bool UnHook() = 0;
		virtual bool IsActive() = 0;
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
		bool Hook() override;
		bool UnHook() override;
		UINT_PTR GetTrampolinAddress();
		UINT_PTR GetHookAddress();
		UINT GetTrampolinSize();
		UINT GetTramplinRawSize();
		bool IsActive() override;



	};

	//Only for hooking functions in prologe. 
	class Detour64 : public IHook
	{
	private:
		BYTE m_absJmp[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 }; //last byte is offest to adress where the adress of the function is stores
		BYTE m_relJmp[5] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
		UINT_PTR m_oFuctionAddress = 0; //function Prologe addr
		UINT_PTR m_hFuctionAddress = 0; //fuction Prologe addr of own function
		UINT_PTR m_trampolinAddress = 0; //just to store the address of the hook function <- so less bytes have to be overriden in prologe: 5 istead of 14
		UINT_PTR m_gatewayAddress = 0; //aka original function <- starts with stolen bytes and jmps then back to original function
		UINT m_overridenBytesCount = 0;
		BYTE* m_originalOpcodes = nullptr;
		bool m_useAbsJmpInProloge = false; //if false -> creates trampolin in 2gb range and start abs jump from there
		bool m_bIsHooked = false;

	public:
		Detour64();
		Detour64(UINT_PTR HookAt, UINT_PTR HookFunc, UINT BytesToOverride, bool useAbsJmpInProloge = false);
		~Detour64();
		void Setup(UINT_PTR HookAt, UINT_PTR HookFunc, UINT BytesToOverride, bool useAbsJmpInProloge = false);
		bool Hook() override;
		bool UnHook() override;
		bool IsActive() override;
		UINT_PTR GetOriginalFuctionAddress();
		UINT_PTR GetGatewayAddress(); //cast this to the original function prototype an call it after executing your own code
		UINT_PTR GetHookFunctionAddress();

	private:
		bool TryHookWithTrampolin();
		bool TryHookWithAbsJmpInProloge();
		PVOID AllocateIn2GBRange(UINT_PTR address, SIZE_T dwSize);
	};

	//TODO: maybe create extra class for InstanceVtableHooking?? InplaceVtableHook, InstanceVtableHook?
	class VTableHook : public IHook {
	private:
		UINT_PTR m_vtableAddress = 0;
		UINT_PTR m_vtableEntryAddress = 0;
		UINT m_vtableIndex = 0;
		UINT_PTR m_oFunctionAddress = 0;
		UINT_PTR m_hFunctionAddress = 0;
		UINT_PTR m_instanceAddress = 0;
		bool m_bHooked = false;
		bool m_bCopyCreated = false;
		LPVOID m_pCopy = nullptr;

	public:
		VTableHook(UINT_PTR VTableAddress, UINT TableIndex, UINT_PTR HookFunc);
		VTableHook(UINT_PTR VTableEntryAddress, UINT_PTR HookFunc);
		void Setup(UINT_PTR VTableAddress, UINT TableIndex, UINT_PTR HookFunc);
		void Setup(UINT_PTR VTableEntryAddress, UINT_PTR HookFunc);
		void Setup(UINT_PTR InstanceAddress, UINT TableIndex, bool createVtableCopy, UINT_PTR HookFunc); //TODO:
		UINT_PTR GetHookFunctionAddress();
		UINT_PTR GetOriginalFuctionAddress();
		UINT_PTR GetOriginalVTableAddress();
		UINT_PTR GetVTableCopyAddress();
		UINT_PTR GetUsedInstanceAddress();
		UINT GetVTableIndex();
		bool Hook() override;
		bool UnHook() override;
		bool IsActive() override;
	};

	/*class CallHook64 : public IHook
	{
	public:
		bool Hook();
		bool UnHook();
	};*/


}

