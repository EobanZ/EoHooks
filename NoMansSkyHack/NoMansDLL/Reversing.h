#pragma once
#include <stdint.h>

class PlayerClass
{
public:
	char pad_0000[3620]; //0x0000
	uint32_t Units; //0x0E24
	uint32_t Nanit; //0x0E28
	uint32_t Quecksilber; //0x0E2C
}; //Size: 0x0E30

class InventarItem
{
public:
	char pad_0000[8]; //0x0000
	char Name[16]; //0x0008
	uint32_t CurrentAmount; //0x0018
	uint32_t MaxAmount; //0x001C
	char pad_0020[8]; //0x0020
	int32_t Column; //0x0028
	int32_t Row; //0x002C
}; //Size: 0x0030

class Inventar //Same for Spacecraft. Find different Pointer
{
public:
	class InventarItem InventarItem[32]; //0x0000
}; //Size: 0x0600

//Offsets
