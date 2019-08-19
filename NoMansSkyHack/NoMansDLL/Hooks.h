#pragma once
#include <Windows.h>
namespace Hooks {
	
	
	bool JmpHook(UINT_PTR HookAt, BYTE* Trampolin, UINT SizeOfTrampolin, UINT BytesToOverride, UINT_PTR* TrampolinAddy);
}

