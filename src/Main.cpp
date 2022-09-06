#include <iostream>
#include "MyHook.h"
#include "windows.h"
#include "struct.h"
#include "winnt.h"
using namespace std;

MyHook g_MyNtOpenFileHook;
MyHook g_MyNtMapViewOfSectionHook;

int main()
{
    g_MyNtOpenFileHook.Start("ntdll.dll", "NtOpenFile", (FARPROC)MyNtOpenFile);
    cout << "测试即将开始" << endl;
    LoadLibraryW(L"advapi32res.dll");
    cout << "测试完成" << endl;
    system("pause");
}

#if _WIN64
NTSTATUS MyNtOpenFile(PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions) 
#elif _WIN32
NTSTATUS __stdcall MyNtOpenFile(PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions)
#endif
{

	g_MyNtOpenFileHook.Suspended();
	//先暂停Hook
	NTSTATUS result;
	result = ((MyNtOpenFileCall)g_MyNtOpenFileHook.GetOldFunction())(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		ShareAccess,
		OpenOptions);
	//调用原函数
	if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"advapi32res.dll")) {
		//如果是加载的advapi32res.dll
		g_MyNtOpenFileHook.Stop();
		//取消Hook
		g_MyNtMapViewOfSectionHook.Start("ntdll.dll", "NtMapViewOfSection", (FARPROC)MyNtMapViewOfSection);
		return result;
	}
	g_MyNtOpenFileHook.Restore();
	//恢复Hook
	return result;
}
//NtMapViewOfSection的Hook处理函数
#if _WIN64
NTSTATUS MyNtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	ULONG InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
) 
#elif _WIN32
NTSTATUS __stdcall MyNtMapViewOfSection(
	HANDLE SectionHandle,
	HANDLE ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	SIZE_T CommitSize,
	PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize,
	ULONG InheritDisposition,
	ULONG AllocationType,
	ULONG Win32Protect
)
#endif
{
	g_MyNtMapViewOfSectionHook.Stop();
#if _WIN64
	HANDLE MyFileHandle = CreateFileW(L".\\CDll_x64.dll",
		GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
#elif _WIN32
	HANDLE MyFileHandle = CreateFileW(L".\\CDll_x86.dll",
		GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
#endif
	//打开文件
	int file_length = GetFileSize(MyFileHandle, NULL);
	//获取文件大小
	byte* DllData = new byte[file_length];
	//将文件读入内存
	ReadFile(MyFileHandle, &DllData[0], file_length, NULL, NULL);
	//用自己的函数实现NtMapViewOfSection：
	MyMapDll(DllData, BaseAddress, ViewSize);
	CloseHandle(MyFileHandle);
	return 0x40000003;//告诉ntdll：{映像重定位}无法在映像文件中指定的地址映射该映像文件。必须对映像文件进行本地修正。
}

void MyMapDll(byte* DllData,
    PVOID* BaseAddress,
    PSIZE_T ViewSize
) {
	//获取基地址
    __int64 DllMemoryBase = (__int64)&DllData[0];
    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER)DllMemoryBase;
	//读出文件DOS头
    if (DOSHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		//检测MZ头
        PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)(DllMemoryBase + DOSHeader->e_lfanew);
        if (NTHeader->Signature == IMAGE_NT_SIGNATURE) {
			//检测PE头
            PVOID l_location, l_lpBaseAddress;
            PIMAGE_SECTION_HEADER Sectionheaders;
            __int64 SectionOffset;
            SectionOffset = DOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS);//IMAGE_SECTION_HEADER在内存中的偏移
            *BaseAddress = VirtualAlloc(NULL, 
				NTHeader->OptionalHeader.SizeOfImage, 
				MEM_COMMIT, 
				PAGE_EXECUTE_READWRITE);
			//分配一块内存供给Dll使用
            *ViewSize = NTHeader->OptionalHeader.SizeOfImage;
			//下面开始根据SECTION信息将Dll数据逐步映射到内存
            int l_count = NTHeader->FileHeader.NumberOfSections;
			//拷贝DOS头
            RtlMoveMemory(*BaseAddress, &DllData[0], SectionOffset + sizeof(IMAGE_SECTION_HEADER) * l_count);
			//设置头部的保护
			VirtualProtect(&DllData[0], 0x1000, PAGE_READONLY, 0);
            for (int i = 0; i < l_count; i++) {
                Sectionheaders = (PIMAGE_SECTION_HEADER)(DllMemoryBase + SectionOffset);
                if (Sectionheaders->PointerToRawData != 0) {
					//如果Sectionheaders->PointerToRawData不为0，表示该段是有数据的，需要拷贝。
					l_location = (PVOID)(DllMemoryBase + Sectionheaders->PointerToRawData);
					l_lpBaseAddress = (PVOID)((__int64)*BaseAddress + Sectionheaders->VirtualAddress);
					//将段数据拷贝到分配的内存中
                    RtlMoveMemory(l_lpBaseAddress, l_location, Sectionheaders->SizeOfRawData);
					//设置保护
                    VirtualProtect(l_lpBaseAddress, 
						Sectionheaders->Misc.VirtualSize, 
						GetProtect(Sectionheaders->Characteristics), 
						0);
                }
                SectionOffset += sizeof(IMAGE_SECTION_HEADER);
				//读取下一个SECTION
            }
        }
    }
}
//这个Characteristics转Protect属性写得有点丑，就这样吧
DWORD GetProtect(DWORD Characteristics) {
    if (Characteristics | IMAGE_SCN_MEM_EXECUTE) {
        if (Characteristics | IMAGE_SCN_MEM_READ) {
            if (Characteristics | IMAGE_SCN_MEM_WRITE) {
                return PAGE_EXECUTE_READWRITE;
            }
            else {
                return PAGE_EXECUTE_READ;
            }
        }
        else
        {
            if (Characteristics | IMAGE_SCN_MEM_WRITE) {
                return PAGE_EXECUTE_WRITECOPY;
            }
            else
            {
                return PAGE_EXECUTE;
            }
        }
    }
    else {
		if (Characteristics | IMAGE_SCN_MEM_READ) {
			if (Characteristics | IMAGE_SCN_MEM_WRITE) {
				return PAGE_READWRITE;
			}
			else {
				return PAGE_READONLY;
			}
		}
		else
		{
			if (Characteristics | IMAGE_SCN_MEM_WRITE) {
				return PAGE_WRITECOPY;
			}
			else
			{
				return PAGE_NOACCESS;
			}
		}
    }
}
