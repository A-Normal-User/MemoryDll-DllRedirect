#include <iostream>
#include "MyHook.h"
#include "windows.h"
#if _WIN64
DWORD OldProtect;
BOOL IsStart;
BYTE OldOPCode[12];
BYTE NewOPCode[12] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
FARPROC TargetFuction;
MyHook::MyHook() {
	//std::cout << "MyHook类被初始化\n";
	IsStart = false;
}
MyHook::~MyHook() {
	//std::cout << "MyHook类被销毁\n";
}
bool MyHook::Start(LPCSTR lpLibFileName, LPCSTR lpProcName, FARPROC DealFuction) {
	if (IsStart) {
		return false;
	}
	TargetFuction = GetProcAddress(GetModuleHandleA(lpLibFileName), lpProcName);
	//读取函数地址
	if (TargetFuction == 0) {
		return false;
	}
	VirtualProtect(TargetFuction, 0xC, PAGE_EXECUTE_READWRITE, &OldProtect);
	//修改保护
	memcpy(&OldOPCode[0], TargetFuction, 0xC);
	//读取出原来的12个字节
	__int64 cache = (__int64)DealFuction;
	memcpy(&NewOPCode[2], &cache, 0x8);
	/*NewOPCode代表汇编代码：
	* mov rax,目标地址
	* jmp rax
	*/
	memcpy(TargetFuction, &NewOPCode[0], 0xC);
	//修改原函数
	IsStart = true;
	return true;
}
bool MyHook::Stop() {
	if (!IsStart) {
		return false;
	}
	memcpy(TargetFuction, &OldOPCode[0], 0xC);
	//恢复原函数
	RtlZeroMemory(&OldOPCode[0], 12);
	IsStart = false;
	return VirtualProtect(TargetFuction, 0xC, OldProtect, &OldProtect);
	//恢复原保护类型
}
VOID MyHook::Suspended() {
	if (IsStart) {
		memcpy(TargetFuction, &OldOPCode[0], 0xC);
		//拷贝回原12个字节实现暂停
	}
}
VOID MyHook::Restore() {
	if (IsStart) {
		memcpy(TargetFuction, &NewOPCode[0], 0xC);
		//拷贝回修改后的12个字节实现恢复
	}
}
FARPROC MyHook::GetOldFunction() {
	return TargetFuction;
	//返回原函数地址
}
#elif _WIN32
DWORD OldProtect;
BOOL IsStart;
BYTE OldOPCode[5];
BYTE NewOPCode[5];
FARPROC TargetFuction;
MyHook::MyHook() {
	//std::cout << "MyHook类被初始化\n";
	IsStart = false;
}
MyHook::~MyHook() {
	//std::cout << "MyHook类被销毁\n";
}
bool MyHook::Start(LPCSTR lpLibFileName, LPCSTR lpProcName, FARPROC DealFuction) {
	if (IsStart) {
		return false;
	}
	TargetFuction = GetProcAddress(GetModuleHandleA(lpLibFileName), lpProcName);
	//读取函数地址
	if (TargetFuction == 0) {
		return false;
	}
	VirtualProtect(TargetFuction, 5, PAGE_EXECUTE_READWRITE, &OldProtect);
	//修改前5个字节的属性
	memcpy(&OldOPCode[0], TargetFuction, 5);
	//读出前5个字节
	NewOPCode[0] = 0xE9;
	int loc = (int)DealFuction - (int)TargetFuction - 5;
	//计算直接跳转的偏移
	memcpy(&NewOPCode[1], &loc, 4);
	//修改前5个字节
	memcpy(TargetFuction, &NewOPCode[0], 5);
	IsStart = true;
	return true;
}
bool MyHook::Stop() {
	if (!IsStart) {
		return false;
	}
	memcpy(TargetFuction, &OldOPCode[0], 5);
	RtlZeroMemory(&OldOPCode[0], 5);
	RtlZeroMemory(&NewOPCode[0], 5);
	IsStart = false;
	return VirtualProtect(TargetFuction, 5, OldProtect, &OldProtect);
}
VOID MyHook::Suspended() {
	if (IsStart) {
		memcpy(TargetFuction, &OldOPCode[0], 5);
	}
}
VOID MyHook::Restore() {
	if (IsStart) {
		memcpy(TargetFuction, &NewOPCode[0], 5);
	}
}
FARPROC MyHook::GetOldFunction() {
	return TargetFuction;
}
#endif