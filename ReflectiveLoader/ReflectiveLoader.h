
#pragma once
#include <windows.h>
#include <Winternl.h>   
#include <iostream>
#include <intrin.h>
using namespace std;  //命名空间



namespace REFLECTIVELOADER
{
	typedef HMODULE(WINAPI *LPFN_LOADLIBRARYA) (_In_ LPCSTR);
	typedef LPVOID(WINAPI *LPFN_GETPROCADDRESS) (HMODULE, LPCSTR);
	typedef LPVOID(WINAPI *LPFN_VIRTUALALLOC) (LPVOID, SIZE_T, DWORD, DWORD);
	typedef VOID(WINAPI *LPFN_EXITTHREAD) (DWORD);
	typedef NTSTATUS(NTAPI *LPFN_NTFLUSHINSTRUCTIONCACHE) (HANDLE, PVOID, ULONG);
	typedef BOOL (WINAPI * LPFN_DLLMAIN)( HINSTANCE, DWORD, LPVOID );
	typedef BOOL (WINAPI * LPFN_MYFUNCTION)( LPVOID, DWORD );
}


#define DEREFERENCE(Value) *(UINT_PTR *)(Value)
#define DEREFERENCE_64(Value) *(DWORD64 *)(Value)
#define DEREFERENCE_32(Value) *(DWORD *)(Value)
#define DEREFERENCE_16(Value) *(WORD *)(Value)
#define DEREFERENCE_8 (Value) *(BYTE *)(Value)

#define KERNEL32DLL_HASH				0x6A4ABC5B
#define NTDLLDLL_HASH					0x3CFA685D

#define LOADLIBRARYA_HASH				0xEC0E4E8E
#define GETPROCADDRESS_HASH				0x7C0DFCAA
#define VIRTUALALLOC_HASH				0x91AFCA54
#define EXITTHREAD_HSAH					0x60E0CEEF
#define NTFLUSHINSTRUCTIONCACHE_HASH			0x534C0AB8
#define RTLEXITUSERTHREAD_HASH				0xFF7F061A 



typedef struct
{
	WORD	Offset : 12;
	WORD	Type : 4;
}IMAGE_BASE_RELOCATION_ITEM, *PIMAGE_BASE_RELOCATION_ITEM;




#define HASH_KEY						13
//===============================================================================================//
#pragma intrinsic( _rotr )
__forceinline DWORD ror(DWORD Value)
{
	return _rotr(Value, HASH_KEY);   //将Value转换为二进制后向右循环移动13位
}
__forceinline DWORD MakeHashValue(char * StringData)
{
	register DWORD HashValue = 0;
	do
	{
		HashValue = ror(HashValue);
		HashValue += *StringData;
	} while (*++StringData);

	return HashValue;
}

