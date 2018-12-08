// Inject.cpp : 定义控制台应用程序的入口点。
//

#include "Inject.h"

LPFN_ISWOW64PROCESS __IsWow64Process = NULL;


static BYTE __ExecutexX64[] = "\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

static BYTE __FunctionX64[] = "\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
"\x48\x83\xC4\x50\x48\x89\xFC\xC3";



int main()
{

	HANDLE FileHandle = NULL;
	ULONG  FileLength = 0;
	LPVOID FileData = NULL;
	ULONG  ReturnLength = 0;
	HANDLE ProcessHandle = NULL;
	HANDLE RemoteThreadHandle = NULL;
	DWORD  ExitCode = 0;
	if (SeEnableSeDebugPrivilege(L"SeDebugPrivilege", TRUE) == FALSE)
	{
		return 0;
	}

	DWORD ProcessID = 0;
	printf("Input ProcessID:\r\n");
	scanf("%d", &ProcessID);


#ifdef _WIN64
	char* DllFullPath = "ReflectiveLoader.dll";
#else
	
	char* DllFullPath = "ReflectiveLoader.dll";
#endif

	FileHandle = CreateFileA(DllFullPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		printf("CreateFileA() Error\r\n");
		goto Exit;
	}


	

	FileLength = GetFileSize(FileHandle, NULL);
	if (FileLength == INVALID_FILE_SIZE || FileLength == 0)
	{
		printf("GetFileSize() Error\r\n");
		goto Exit;
	}

	FileData = HeapAlloc(GetProcessHeap(), 0, FileLength);
	if (!FileData)
	{
		printf("HeapAlloc() Error\r\n");
		goto Exit;
	}

	if (ReadFile(FileHandle, FileData, FileLength, &ReturnLength, NULL) == FALSE)
	{
		printf("HeapAlloc() Error\r\n");
		goto Exit;
	}

	ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
		FALSE, ProcessID);
	if (!ProcessHandle)
	{
		printf("OpenProcess() Error\r\n");
		goto Exit;
	}

	RemoteThreadHandle = SeLoadRemoteLibrary(ProcessHandle, FileData, FileLength, NULL,MYFUNCTION_HASH,(LPVOID)"911",strlen("911")+1);
	if (!RemoteThreadHandle)
	{
		printf("SeLoadRemoteLibrary() Error\r\n");
		goto Exit;
	}
	
	printf("SeLoadRemoteLibrary() Success\r\n");

	WaitForSingleObject(RemoteThreadHandle, INFINITE);

	if (!GetExitCodeThread(RemoteThreadHandle, &ExitCode))

	
	printf("Input AnyKey To Exit\r\n");
	getchar();
Exit:

	if (FileData)
	{
		HeapFree(GetProcessHeap(), 0, FileData);
	}
    if (FileHandle!=NULL)
    {
		CloseHandle(FileHandle);
		FileHandle = NULL;
    }
	

	if (ProcessHandle)
	{
		CloseHandle(ProcessHandle);
		ProcessHandle = NULL;
	}
		

    return 0;
}

BOOL SeEnableSeDebugPrivilege(IN const WCHAR*  PriviledgeName, BOOL IsEnable)
{
	// 打开权限令牌

	HANDLE  ProcessHandle = GetCurrentProcess();
	HANDLE  TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	if (!OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		return FALSE;
	}
	LUID			 v1;
	if (!LookupPrivilegeValue(NULL, PriviledgeName, &v1))		// 通过权限名称查找uID
	{
		CloseHandle(TokenHandle);
		TokenHandle = NULL;
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;		// 要提升的权限个数
	TokenPrivileges.Privileges[0].Attributes = IsEnable == TRUE ? SE_PRIVILEGE_ENABLED : 0;    // 动态数组，数组大小根据Count的数目
	TokenPrivileges.Privileges[0].Luid = v1;


	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges,
		sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("%d\r\n", GetLastError());
		CloseHandle(TokenHandle);
		TokenHandle = NULL;
		return FALSE;
	}
	CloseHandle(TokenHandle);
	TokenHandle = NULL;
	return TRUE;
}
HANDLE WINAPI SeLoadRemoteLibrary(
	HANDLE ProcessHandle,
	LPVOID FileData,   //Dll文件数据
	DWORD  FileLength,
	LPVOID ParameterData,
	DWORD  FunctionHash,
	LPVOID UserData,
	DWORD  UserDataLength)
{
	HANDLE RemoteThreadHandle = NULL;
	DWORD  RemoteThreadID = 0;
	DWORD TargetArchitecture = X86; 
	DWORD DllArchitecture = UNKNOWN;

#if defined(_WIN64)
	DWORD CurrentArchitecture = X64;
#elif defined (_WIN32)
	DWORD CurrentArchitecture = X86;
#else

#endif

	__try
	{
		do
		{

			if (!ProcessHandle || !FileData || !FileLength)
				break;

			// 获得目标进程的Architecture
			HMODULE KernelModuleBase = LoadLibraryA("kernel32.dll");
			if (!KernelModuleBase)
				break;
			__IsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(KernelModuleBase, "IsWow64Process");
			FreeLibrary(KernelModuleBase);
			if (__IsWow64Process) 
			{
				BOOL IsWow64;
				if (!__IsWow64Process(ProcessHandle, &IsWow64))
					break;
				if (IsWow64)
					TargetArchitecture = X86;
				else {
					SYSTEM_INFO SystemInfo = { 0 };
					GetNativeSystemInfo(&SystemInfo);
					if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
						TargetArchitecture = X64;
					else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
						TargetArchitecture = X86;
					else
						break;
				}
			}

			// 获得Dll的Architecture
			PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(((PUINT8)FileData) + ((PIMAGE_DOS_HEADER)FileData)->e_lfanew);
			if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
				DllArchitecture = X86;
			else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
				DllArchitecture = X64;

			// DLL and target process must be same architecture
			if (DllArchitecture != TargetArchitecture)
			{
				printf("Must Be Same Architecture\r\n");
				break;
			}
				
			// check if the library has a ReflectiveLoader...
			DWORD ReflectiveLoaderOffset = SeGetReflectiveLoaderOffset(FileData);
			if (!ReflectiveLoaderOffset)
			{
				printf("Could Not Get ReflectiveLoader Offset\r\n");
				break;
			}
	
			DWORD RemoteBufferLength = FileLength
				+ UserDataLength
				+ 64; // shellcode buffer

			// alloc memory (RWX) in the host process for the image...
			LPVOID RemoteBufferData = VirtualAllocEx(ProcessHandle, NULL, RemoteBufferLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!RemoteBufferData)
				break;
			printf("VirtualAllocEx() Success\r\n");

			// write the image into the host process...
			if (!WriteProcessMemory(ProcessHandle, RemoteBufferData, FileData, FileLength, NULL))
				break;

			ULONG_PTR ReflectiveLoader = (ULONG_PTR)RemoteBufferData + ReflectiveLoaderOffset;

			// write our userdata blob into the host process
			ULONG_PTR RemoteUserData = (ULONG_PTR)RemoteBufferData + FileLength;
			if (!WriteProcessMemory(ProcessHandle, (LPVOID)RemoteUserData, UserData, UserDataLength, NULL))
				break;

			ULONG_PTR RemoteShellCode = RemoteUserData + UserDataLength;

			BYTE Bootstrap[64] = { 0 };
			DWORD BootstrapLength = SeCreateBootstrap(
				Bootstrap,
				64,
				TargetArchitecture,
				(ULONG_PTR)ParameterData,
				(ULONG_PTR)RemoteBufferData,
				FunctionHash,
				RemoteUserData,
				UserDataLength,
				ReflectiveLoader);
			if (BootstrapLength <= 0)
				break;


			printf("%p\r\n", RemoteShellCode);
			getchar();
			// finally, write our shellcode into the host process
			if (!WriteProcessMemory(ProcessHandle, (LPVOID)RemoteShellCode, Bootstrap, BootstrapLength, NULL))
				break;
			printf("Wrote ShellCode Success\r\n");

			// Make sure our changes are written right away
			FlushInstructionCache(ProcessHandle, RemoteBufferData, RemoteBufferLength);

			// 目标64  当前32
	
			printf("%p\r\n", RemoteShellCode);
			getchar();
			getchar();
			if (CurrentArchitecture == X86 && TargetArchitecture == X64) {
				Wow64CreateRemoteThread(ProcessHandle, (LPVOID)RemoteShellCode, ParameterData, &RemoteThreadHandle);
				ResumeThread(RemoteThreadHandle);
			}
			else {
				//目标32  当前32
				//目标64  当前64
				//目标32  当前64
				RemoteThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 1024 * 1024,
					(LPTHREAD_START_ROUTINE)RemoteShellCode, ParameterData, 
					(DWORD)NULL, &RemoteThreadID);
			}

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		RemoteThreadHandle = NULL;
	}

	return RemoteThreadHandle;
}
DWORD SeGetReflectiveLoaderOffset(VOID* BufferData)
{

	UINT_PTR ImageBaseAddress = 0;
	PIMAGE_NT_HEADERS ImageNtHeaders = NULL;
	ULONG_PTR ImageDataDirectory = 0;
	ULONG_PTR ImageExportDirectory = NULL;
	ULONG_PTR AddressOfNames = 0;
	ULONG_PTR AddressOfFunctions = 0;
	ULONG_PTR AddressOfNameOrdinals = 0;
	DWORD     NumberOfNames = 0;

	ImageBaseAddress = (UINT_PTR)BufferData;

	// get the File Offset of the modules NT Header
	ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageBaseAddress + ((PIMAGE_DOS_HEADER)ImageBaseAddress)->e_lfanew);

	if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
	{

		ImageDataDirectory = (UINT_PTR)&((PIMAGE_NT_HEADERS32)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
	{
		
		ImageDataDirectory = (UINT_PTR)&((PIMAGE_NT_HEADERS64)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else
	{
		return 0;
	}

	// get the File Offset of the export directory  //内存对齐转换为文件对齐
	ImageExportDirectory = ImageBaseAddress + RvaToOffset(((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress, ImageBaseAddress);

	// get the File Offset for the array of name pointers
	AddressOfNames = ImageBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames, ImageBaseAddress);

	// get the File Offset for the array of addresses
	AddressOfFunctions = ImageBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions, ImageBaseAddress);

	// get the File Offset for the array of name ordinals
	AddressOfNameOrdinals = ImageBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals, ImageBaseAddress);

	// get a counter for the number of exported functions...
	NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while (NumberOfNames--)
	{
		char * FunctionName = (char *)(ImageBaseAddress + RvaToOffset(DEREFERENCE_32(AddressOfNames), ImageBaseAddress));

		if (strstr(FunctionName, "ReflectiveLoader") != NULL)
		{
			// get the File Offset for the array of addresses
			AddressOfFunctions = ImageBaseAddress + RvaToOffset(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions, ImageBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			return RvaToOffset(DEREFERENCE_32(AddressOfFunctions), ImageBaseAddress);
		}
		// get the next exported function name
		AddressOfNames += sizeof(DWORD);

		// get the next exported function name ordinal
		AddressOfNameOrdinals += sizeof(WORD);
	}

	return 0;
}

DWORD RvaToOffset(DWORD Rva, UINT_PTR ImageBaseAddress)   //ImageBaseAddress = ReadFile中的BufferData = "MZ     0x00004550 PE00"
{
	WORD i = 0;
	WORD NumberOfSections = 0;
	PIMAGE_SECTION_HEADER ImageSectionHeader = NULL;

	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageBaseAddress + ((PIMAGE_DOS_HEADER)ImageBaseAddress)->e_lfanew);
	if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
	{
		PIMAGE_NT_HEADERS32 ImageNtHeaders32 = (PIMAGE_NT_HEADERS32)ImageNtHeaders;
		
		ImageSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ImageNtHeaders32->OptionalHeader) + ImageNtHeaders32->FileHeader.SizeOfOptionalHeader);
		NumberOfSections = ImageNtHeaders32->FileHeader.NumberOfSections;
	}
	else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
	{
		PIMAGE_NT_HEADERS64 ImageNtHeaders64 = (PIMAGE_NT_HEADERS64)ImageNtHeaders;
		ImageSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ImageNtHeaders64->OptionalHeader) + ImageNtHeaders64->FileHeader.SizeOfOptionalHeader);
		NumberOfSections = ImageNtHeaders64->FileHeader.NumberOfSections;
	}
	else
	{
		return 0;
	}

	if (Rva < ImageSectionHeader[0].PointerToRawData)
		return Rva;

	for (i = 0; i < NumberOfSections; i++)
	{
		if (Rva >= ImageSectionHeader[i].VirtualAddress && Rva < (ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].SizeOfRawData))
		{
			return (Rva - ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].PointerToRawData);
		}		
	}

	return 0;
}

DWORD SeCreateBootstrap(
	LPBYTE Bootstrap,
	DWORD BootstrapLength,
	DWORD TargetArchitecture,
	ULONG_PTR ParameterData,
	ULONG_PTR RemoteBufferData,
	DWORD FunctionHashValue,
	ULONG_PTR UserData,
	DWORD UserDataLength,
	ULONG_PTR ReflectiveLoader)
{
	DWORD i = 0;

	if (BootstrapLength < 64)
		return 0;

#if defined(_WIN64)
	DWORD CurrentArchitecture = X64;
#elif defined(_WIN32)
	DWORD CurrentArchitecture = X86;
#else

#endif

	if (TargetArchitecture == X86) 
	{
		// push <size of userdata>
		Bootstrap[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(Bootstrap + i, &UserDataLength, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <address of userdata>
		Bootstrap[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(Bootstrap + i, &UserData, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <hash of function>
		Bootstrap[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(Bootstrap + i, &FunctionHashValue, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <address of image base>
		Bootstrap[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(Bootstrap + i, &RemoteBufferData, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <lpParameter>
		Bootstrap[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(Bootstrap + i, &ParameterData, sizeof(DWORD));
		i += sizeof(DWORD);

		// mov eax, <address of reflective loader>
		Bootstrap[i++] = 0xB8; // MOV EAX (word/dword)
		MoveMemory(Bootstrap + i, &ReflectiveLoader, sizeof(DWORD));
		i += sizeof(DWORD);

		// call eax
		Bootstrap[i++] = 0xFF; // CALL
		Bootstrap[i++] = 0xD0; // EAX

	}
	else if (TargetArchitecture == X64) {
		if (CurrentArchitecture == X86) {
			// mov rcx, <lpParameter>
			MoveMemory(Bootstrap + i, "\x48\xc7\xc1", 3);
			i += 3;
			MoveMemory(Bootstrap + i, &ParameterData, sizeof(ParameterData));
			i += sizeof(ParameterData);

			// mov rdx, <address of image base>
			MoveMemory(Bootstrap + i, "\x48\xc7\xc2", 3);
			i += 3;
			MoveMemory(Bootstrap + i, &RemoteBufferData, sizeof(RemoteBufferData));
			i += sizeof(RemoteBufferData);

			// mov r8d, <hash of function>
			MoveMemory(Bootstrap + i, "\x41\xb8", 2);
			i += 2;
			MoveMemory(Bootstrap + i, &FunctionHashValue, sizeof(FunctionHashValue));
			i += sizeof(FunctionHashValue);

			// mov r9, <address of userdata>
			MoveMemory(Bootstrap + i, "\x49\xc7\xc1", 3);
			i += 3;
			MoveMemory(Bootstrap + i, &UserData, sizeof(UserData));
			i += sizeof(UserData);

			// push <size of userdata>
			Bootstrap[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(Bootstrap + i, &UserDataLength, sizeof(UserDataLength));
			i += sizeof(UserDataLength);

			// sub rsp, 20
			MoveMemory(Bootstrap + i, "\x48\x83\xec\x20", 4);
			i += 4;

			// move rax, <address of reflective loader>
			MoveMemory(Bootstrap + i, "\x48\xc7\xc0", 3);
			i += 3;
			MoveMemory(Bootstrap + i, &ReflectiveLoader, sizeof(ReflectiveLoader));
			i += sizeof(ReflectiveLoader);

		}
		else {
			// mov rcx, <lpParameter>
			MoveMemory(Bootstrap + i, "\x48\xb9", 2);
			i += 2;
			MoveMemory(Bootstrap + i, &ParameterData, sizeof(ParameterData));
			i += sizeof(ParameterData);

			// mov rdx, <address of image base>
			MoveMemory(Bootstrap + i, "\x48\xba", 2);
			i += 2;
			MoveMemory(Bootstrap + i, &RemoteBufferData, sizeof(RemoteBufferData));
			i += sizeof(RemoteBufferData);

			// mov r8d, <hash of function>
			MoveMemory(Bootstrap + i, "\x41\xb8", 2);
			i += 2;
			MoveMemory(Bootstrap + i, &FunctionHashValue, sizeof(FunctionHashValue));
			i += sizeof(FunctionHashValue);

			// mov r9, <address of userdata>
			MoveMemory(Bootstrap + i, "\x49\xb9", 2);
			i += 2;
			MoveMemory(Bootstrap + i, &UserData, sizeof(UserData));
			i += sizeof(UserData);

			// push <size of userdata>
			Bootstrap[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(Bootstrap + i, &UserDataLength, sizeof(UserDataLength));
			i += sizeof(UserDataLength);

			// sub rsp, 20
			MoveMemory(Bootstrap + i, "\x48\x83\xec\x20", 4);
			i += 4;

			// move rax, <address of reflective loader>
			MoveMemory(Bootstrap + i, "\x48\xb8", 2);
			i += 2;
			MoveMemory(Bootstrap + i, &ReflectiveLoader, sizeof(ReflectiveLoader));
			i += sizeof(ReflectiveLoader);
		}

		// call rax
		Bootstrap[i++] = 0xFF; // CALL
		Bootstrap[i++] = 0xD0; // RAX
	}

	return i;
}

DWORD Wow64CreateRemoteThread(HANDLE ProcessHandle, LPVOID ThreadProcedure, LPVOID ParameterData, HANDLE * ThreadHandle)
{
	DWORD dwResult = ERROR_SUCCESS;
	LPFN_EXECUTEX64  ExecuteX64 = NULL;
	LPFN_FUNCTIONX64 FunctionX64 = NULL;

	WOW64CONTEXT*  Wow64Context = NULL;
	OSVERSIONINFO  OsVersionInfo = { 0 };

	do
	{
		OsVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

		if (!GetVersionEx(&OsVersionInfo))
		{
			printf("GetVersionEx() Error\r\n");
			break;
		}
		
			// filter out Windows 2003
		if (OsVersionInfo.dwMajorVersion == 5 && OsVersionInfo.dwMinorVersion == 2)
		{
				
			printf("Is 2003 Error\r\n");
			break;
		}
		ExecuteX64 = (LPFN_EXECUTEX64)VirtualAlloc(NULL, sizeof(__ExecutexX64), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!ExecuteX64)
		{

			printf("VirtualAlloc() Error\r\n");
			break;
		}

		FunctionX64 = (LPFN_FUNCTIONX64)VirtualAlloc(NULL, sizeof(__FunctionX64) + sizeof(WOW64CONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!FunctionX64)
		{

			printf("VirtualAlloc() Error\r\n");
			break;
		}
			// copy over the wow64->x64 stub
		memcpy(ExecuteX64, &__ExecutexX64, sizeof(__ExecutexX64));

		// copy over the native x64 function
		memcpy(FunctionX64, &__FunctionX64, sizeof(__FunctionX64));

		// set the context
		Wow64Context = (WOW64CONTEXT *)((BYTE *)FunctionX64 + sizeof(__FunctionX64));

		Wow64Context->u1.ProcessHandle   = ProcessHandle;   //目标进程句柄
		Wow64Context->u2.ThreadProcedure = ThreadProcedure;
		Wow64Context->u3.ParameterData   = ParameterData;
		Wow64Context->u4.ThreadHandle    = NULL;

		//执行该代码的环境是32位
		if (!ExecuteX64(FunctionX64, (DWORD)Wow64Context))  
		{		
			printf("ExecuteX64() Error\r\n");
			break;
		}

		if (!Wow64Context->u4.ThreadHandle)
		{		
			printf("ThreadHandle Is NULL\r\n");
			break;
		}

		// Success! grab the new thread handle from of the context
		*ThreadHandle = Wow64Context->u4.ThreadHandle;

	} while (0);

	if (ExecuteX64)
	{
		VirtualFree(ExecuteX64, 0, MEM_RELEASE);
		ExecuteX64 = NULL;
	}
		

	if (FunctionX64)
	{
		VirtualFree(FunctionX64, 0, MEM_RELEASE);
		FunctionX64 = NULL;
	}
		

	return dwResult;
}