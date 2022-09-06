# MemoryDll-DllRedirect
   - 这是一种很奇怪的实现Dll重定向到内存的方法。
   - 利用Hook实现。
   - 只能在Windows上使用。
   - Hook了NtOpenFile和NtMapViewOfSection。

# 源码解析：
   - MyHook.cpp里面仅仅是一个简单的APIHOOK，
      - 兼容x64和x86
	  - 利用修改函数头实现
	  - \*兼容性未知。（可自行替换为自己的APIHOOK）

   - Main.cpp：
      - 首先Hook了NtOpenFile函数。
	  - 然后利用LoadLibraryW加载“advapi32res.dll”（Dll无所谓，只要是一个Dll就行，这个Dll只是一个傀儡Dll，后面不会加载它的）
	  - Hook的回调函数大致如下：
	  
```
\#if _WIN64
NTSTATUS MyNtOpenFile(PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions) 
\#elif _WIN32
NTSTATUS __stdcall MyNtOpenFile(PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG OpenOptions)
\#endif
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
		//如果是加载的sxs.dll
		g_MyNtOpenFileHook.Stop();
		//取消Hook
		g_MyNtMapViewOfSectionHook.Start("ntdll.dll", "NtMapViewOfSection", (FARPROC)MyNtMapViewOfSection);
		return result;
	}
	g_MyNtOpenFileHook.Restore();
	//恢复Hook
	return result;
}
```
      - 可以看到，其实加载Dll时先调用NtOpenFile打开Dll文件（内部接着会调用NtCreateSection和NtMapViewOfSection对文件句柄进行映射）

## 实现结果：
   - x64测试：![](./png/x64.png)
   - x86测试：![](./png/x86.png)
