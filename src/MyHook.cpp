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
	//std::cout << "MyHook�౻��ʼ��\n";
	IsStart = false;
}
MyHook::~MyHook() {
	//std::cout << "MyHook�౻����\n";
}
bool MyHook::Start(LPCSTR lpLibFileName, LPCSTR lpProcName, FARPROC DealFuction) {
	if (IsStart) {
		return false;
	}
	TargetFuction = GetProcAddress(GetModuleHandleA(lpLibFileName), lpProcName);
	//��ȡ������ַ
	if (TargetFuction == 0) {
		return false;
	}
	VirtualProtect(TargetFuction, 0xC, PAGE_EXECUTE_READWRITE, &OldProtect);
	//�޸ı���
	memcpy(&OldOPCode[0], TargetFuction, 0xC);
	//��ȡ��ԭ����12���ֽ�
	__int64 cache = (__int64)DealFuction;
	memcpy(&NewOPCode[2], &cache, 0x8);
	/*NewOPCode��������룺
	* mov rax,Ŀ���ַ
	* jmp rax
	*/
	memcpy(TargetFuction, &NewOPCode[0], 0xC);
	//�޸�ԭ����
	IsStart = true;
	return true;
}
bool MyHook::Stop() {
	if (!IsStart) {
		return false;
	}
	memcpy(TargetFuction, &OldOPCode[0], 0xC);
	//�ָ�ԭ����
	RtlZeroMemory(&OldOPCode[0], 12);
	IsStart = false;
	return VirtualProtect(TargetFuction, 0xC, OldProtect, &OldProtect);
	//�ָ�ԭ��������
}
VOID MyHook::Suspended() {
	if (IsStart) {
		memcpy(TargetFuction, &OldOPCode[0], 0xC);
		//������ԭ12���ֽ�ʵ����ͣ
	}
}
VOID MyHook::Restore() {
	if (IsStart) {
		memcpy(TargetFuction, &NewOPCode[0], 0xC);
		//�������޸ĺ��12���ֽ�ʵ�ָֻ�
	}
}
FARPROC MyHook::GetOldFunction() {
	return TargetFuction;
	//����ԭ������ַ
}
#elif _WIN32
DWORD OldProtect;
BOOL IsStart;
BYTE OldOPCode[5];
BYTE NewOPCode[5];
FARPROC TargetFuction;
MyHook::MyHook() {
	//std::cout << "MyHook�౻��ʼ��\n";
	IsStart = false;
}
MyHook::~MyHook() {
	//std::cout << "MyHook�౻����\n";
}
bool MyHook::Start(LPCSTR lpLibFileName, LPCSTR lpProcName, FARPROC DealFuction) {
	if (IsStart) {
		return false;
	}
	TargetFuction = GetProcAddress(GetModuleHandleA(lpLibFileName), lpProcName);
	//��ȡ������ַ
	if (TargetFuction == 0) {
		return false;
	}
	VirtualProtect(TargetFuction, 5, PAGE_EXECUTE_READWRITE, &OldProtect);
	//�޸�ǰ5���ֽڵ�����
	memcpy(&OldOPCode[0], TargetFuction, 5);
	//����ǰ5���ֽ�
	NewOPCode[0] = 0xE9;
	int loc = (int)DealFuction - (int)TargetFuction - 5;
	//����ֱ����ת��ƫ��
	memcpy(&NewOPCode[1], &loc, 4);
	//�޸�ǰ5���ֽ�
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