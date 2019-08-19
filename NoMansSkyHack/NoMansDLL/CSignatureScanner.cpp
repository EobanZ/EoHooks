#include "CSignatureScanner.h"

inline char* CSignatureScanner::patternscan(char* pData, UINT_PTR RegionSize, const char* szPattern, const char* szMask, int Len)
{
	for (UINT i = 0; i != RegionSize - Len; ++i, ++pData)
		if (comparePattern(pData, szPattern, szMask))
			return pData;

	return nullptr;
}

inline bool CSignatureScanner::comparePattern(char* szSource, const char* szPattern, const char* szMask)
{
	for (; *szMask; ++szSource, ++szPattern, ++szMask)
		if (*szMask == 'x' && *szSource != *szPattern)
			return false;

	return true;
}

CSignatureScanner::CSignatureScanner():m_lastFoundAddress(0)
{
}

UINT_PTR CSignatureScanner::GetLastScanResult()
{
	return m_lastFoundAddress;
}

char* CSignatureScanner::PatternScanInt(char* pStart, UINT_PTR RegionSize, Signature signature)
{
	char* pCurrent = pStart;
	const char* szPattern = signature.szPattern;
	const char* szMask = signature.szMask;
	int Len = signature.lenght;

	while (pCurrent <= pStart + RegionSize - Len)
	{
		MEMORY_BASIC_INFORMATION MBI{ 0 };
		if (!VirtualQuery(pCurrent, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
			return nullptr;

		if (MBI.State == MEM_COMMIT && !(MBI.Protect & PAGE_NOACCESS || MBI.Protect & PAGE_GUARD))
		{
			if (pCurrent + MBI.RegionSize > pStart + RegionSize - Len)
				MBI.RegionSize = pStart + RegionSize - pCurrent + Len;

			char* Ret = patternscan(pCurrent, MBI.RegionSize, szPattern, szMask, Len);

			if (Ret && (Ret != szPattern))
			{
				m_lastFoundAddress = reinterpret_cast<UINT_PTR>(Ret);
				return Ret;
			}
				
		}
		pCurrent += MBI.RegionSize;
		Sleep(100);
	}

	return nullptr;
}

char* CSignatureScanner::PatternScanEx(HANDLE hProc, char* pStart, UINT_PTR RegionSize, Signature signature)
{
	DWORD Buffer = 0;
	if (!GetHandleInformation(hProc, &Buffer))
		return nullptr;

	char* pCurrent = pStart;
	const char* szPattern = signature.szPattern;
	const char* szMask = signature.szMask;
	int Len = signature.lenght;

	SIZE_T BufferSize = 0x10000;
	char* Data = new char[BufferSize];

	while (pCurrent <= pStart + RegionSize - Len)
	{
		MEMORY_BASIC_INFORMATION MBI{ 0 };
		if (!VirtualQueryEx(hProc, pCurrent, &MBI, sizeof(MEMORY_BASIC_INFORMATION)))
			return nullptr;

		if (MBI.State == MEM_COMMIT && !(MBI.Protect & (PAGE_NOACCESS | PAGE_GUARD)))
		{
			if (BufferSize < MBI.RegionSize)
			{
				delete[] Data;
				BufferSize = MBI.RegionSize;
				Data = new char[BufferSize];
			}

			UINT_PTR Delta = pCurrent - reinterpret_cast<char*>(MBI.BaseAddress);
			MBI.RegionSize -= Delta;

			if (pCurrent + MBI.RegionSize > pStart + RegionSize - Len)
				MBI.RegionSize -= pCurrent + MBI.RegionSize - pStart - RegionSize + Len;

			if (!ReadProcessMemory(hProc, pCurrent, Data, MBI.RegionSize, nullptr))
			{
				pCurrent = pCurrent + MBI.RegionSize;
				continue;
			}

			char* Ret = patternscan(Data, MBI.RegionSize, szPattern, szMask, Len);

			if (Ret)
			{
				delete[] Data;
				m_lastFoundAddress = reinterpret_cast<UINT_PTR>(Ret - Data + pCurrent);
				return (Ret - Data + pCurrent);
			}
		}

		pCurrent = pCurrent + MBI.RegionSize;
	}

	delete[] Data;

	return nullptr;
}
