#pragma once
#include <Windows.h>

typedef struct _Signature {
	_Signature(const char* pattern, const char* mask) { szPattern = pattern; szMask = mask; lenght = strlen(szMask); }
	const char* szPattern;
	const char* szMask;
	int lenght;
}Signature, *PSignature;



class CSignatureScanner
{
private:
	UINT_PTR m_lastFoundAddress;
	

	inline char* patternscan(char* pData, UINT_PTR RegionSize, const char* szPattern, const char* szMask, int Len);
	inline bool comparePattern(char* szSource, const char* szPattern, const char* szMask);

public:
	CSignatureScanner();
	UINT_PTR GetLastScanResult();
	char* PatternScanInt(char* pStart, UINT_PTR RegionSize, Signature signature);
	char* PatternScanEx(HANDLE hProc, char* pStart, UINT_PTR RegionSize, Signature signature);


};

