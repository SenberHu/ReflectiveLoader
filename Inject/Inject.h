
#pragma once
#include <Windows.h>
#include <Winternl.h>    
#include <iostream>
using namespace std;

#define MYFUNCTION_HASH		0x6654bba6 // hash of "MyFunction"
enum {
	UNKNOWN,
	X86,
	X64
};


#define DEREFERENCE   (Value) *(UINT_PTR *)(Value)
#define DEREFERENCE_64(Value) *(DWORD64 *)(Value)
#define DEREFERENCE_32(Value) *(DWORD *)(Value)
#define DEREFERENCE_16(Value) *(WORD *)(Value)
#define DEREFERENCE_8 (Value) *(BYTE *)(Value)

typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
typedef BOOL(WINAPI *  LPFN_FUNCTIONX64)(DWORD ParameterData);
typedef DWORD(WINAPI * LPFN_EXECUTEX64)(LPFN_FUNCTIONX64 FunctionX64, DWORD ParameterData);


typedef struct _WOW64CONTEXT_
{
	union
	{
		HANDLE ProcessHandle;
		BYTE   Padding[8];
	}u1;

	union
	{
		LPVOID ThreadProcedure;
		BYTE   Padding[8];
	}u2;

	union
	{
		LPVOID ParameterData;
		BYTE   Padding[8];
	}u3;
	union
	{
		HANDLE ThreadHandle;
		BYTE   Padding[8];
	}u4;
} WOW64CONTEXT, *LPWOW64CONTEXT;

BOOL SeEnableSeDebugPrivilege(IN const WCHAR*  PriviledgeName, BOOL IsEnable);
HANDLE WINAPI SeLoadRemoteLibrary(
	HANDLE ProcessHandle,
	LPVOID FileData,   //Dll文件数据
	DWORD  FileLength,
	LPVOID ParameterData,
	DWORD  FunctionHash,
	LPVOID UserData,
	DWORD  UserDataLength);
DWORD SeGetReflectiveLoaderOffset(VOID* BufferData);
DWORD RvaToOffset(DWORD Rva, UINT_PTR ImageBaseAddress);
DWORD SeCreateBootstrap(
	LPBYTE Bootstrap,
	DWORD BootstrapLength,
	DWORD TargetArchitecture,
	ULONG_PTR ParameterData,
	ULONG_PTR RemoteBufferData,
	DWORD FunctionHashValue,
	ULONG_PTR UserData,
	DWORD UserDataLength,
	ULONG_PTR ReflectiveLoader);

DWORD Wow64CreateRemoteThread(HANDLE ProcessHandle, LPVOID ThreadProcedure, LPVOID ParameterData, HANDLE * ThreadHandle);