#include <stdio.h>
#include <Windows.h>

int main()
{

	HMODULE mod = LoadLibraryA("D:\\Repositories\\hacknomanssky\\NoMansSkyHack\\NoMansDLL\\Builds\\NoMansDLL.dll");
	printf_s("Created Module: %X\n", (DWORD)mod);
}