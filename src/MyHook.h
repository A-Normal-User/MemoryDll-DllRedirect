#pragma once
#include "windows.h"
class MyHook
{
public:
	MyHook();
	~MyHook();
public:
	bool Start(LPCSTR lpLibFileName, LPCSTR lpProcName, FARPROC DealFuction);
	bool Stop();
	VOID Suspended();
	VOID Restore();
	FARPROC GetOldFunction();
};

