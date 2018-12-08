// ReflectiveLoader.cpp : 定义 DLL 应用程序的导出函数。
//

#include "ReflectiveLoader.h"

__declspec( dllexport )  
VOID WINAPI ReflectiveLoader(LPVOID ParameterData, ULONG_PTR RemoteBufferData, DWORD FunctionHashValue, 
	LPVOID UserData, DWORD UserDataLength)
{

	PPEB Peb = NULL;
	ULONG_PTR Ldr = 0;
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = NULL;
	ULONG_PTR ModuleName = 0;
	USHORT    ModuleNameLength;
	ULONG_PTR ModuleHashValue;
	ULONG_PTR ImageNtHeaders = NULL;
	ULONG_PTR ImageDataDirectory = 0;
	ULONG_PTR ImageImportDescriptor = NULL;  
	ULONG_PTR ImageExportDirectory  = NULL;
	ULONG_PTR AddressOfNames = 0;
	ULONG_PTR AddressOfFunctions = 0;
	ULONG_PTR AddressOfNameOrdinals = 0;
	DWORD     NumberOfNames = 0;
	DWORD     HashValue = 0;
	DWORD     IsLoop = 0;
	ULONG_PTR VirtualAddress = 0;
	DWORD     SizeOfHeaders = 0;
	BYTE*     v1 = NULL;
	BYTE*     v2 = NULL;
	WORD      NumberOfSections = 0;
	ULONG_PTR SectionVirtualAddress = 0;
	ULONG_PTR SectionPointerToRawData = 0;
	DWORD     SizeOfRawData = 0;
	ULONG_PTR ModuleBase = 0;   //导入模块的基地址
	ULONG_PTR OriginalFirstThunk = 0;
	ULONG_PTR FirstThunk = 0;
	ULONG_PTR ImageImportByName = 0;
	ULONG_PTR Diff = 0;
	ULONG_PTR v3 = 0;
	ULONG_PTR ImageBaseRelocation = NULL;
	ULONG_PTR ImageBaseRelocationItem = 0;
	ULONG_PTR ImageBaseRelocationItemCount = 0;
	ULONG_PTR AddressOfEntryPoint = 0;
	BOOL  IsOk = FALSE;



	REFLECTIVELOADER::LPFN_LOADLIBRARYA   LoadLibraryA = NULL;
	REFLECTIVELOADER::LPFN_GETPROCADDRESS GetProcAddress = NULL;
	REFLECTIVELOADER::LPFN_VIRTUALALLOC   VirtualAlloc = NULL;
	REFLECTIVELOADER::LPFN_EXITTHREAD     ExitThread  = NULL;
	REFLECTIVELOADER::LPFN_EXITTHREAD  RtlExitUserThread = NULL;
	REFLECTIVELOADER::LPFN_NTFLUSHINSTRUCTIONCACHE NtFlushInstructionCache = NULL;


	DWORD ExitCode = 1;

	// STEP 1: process the kernels exports for the functions our loader needs...

	//获得目标进程中Peb
#ifdef _WIN64
	Peb = (PPEB)__readgsqword(0x60);
#else
#ifdef _WIN32
	Peb = (PPEB)__readfsdword(0x30);
#else 
#endif
#endif

	
	Ldr = (ULONG_PTR)Peb->Ldr;


	LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((PPEB_LDR_DATA)Ldr)->InMemoryOrderModuleList.Flink;
	while (LdrDataTableEntry)
	{
	
		ModuleName = (ULONG_PTR)LdrDataTableEntry->FullDllName.Buffer;   //双字

		ModuleNameLength = LdrDataTableEntry->FullDllName.Length;

		ModuleHashValue = 0;
		do
		{
			ModuleHashValue = ror((DWORD)ModuleHashValue);  
		
			if (*((BYTE *)ModuleName) >= 'a')   //转换为大写
				ModuleHashValue += *((BYTE *)ModuleName) - 0x20;
			else
				ModuleHashValue += *((BYTE *)ModuleName);
			ModuleName++;
		} while (--ModuleNameLength);

		//在目标进程中查询Kernel32动态库
		if ((DWORD)ModuleHashValue == KERNEL32DLL_HASH)
		{
			//获得Kerner32.dll的模块地址
			ModuleBase = (ULONG_PTR)LdrDataTableEntry->Reserved2[0];


			ImageNtHeaders = (ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);


			//有两个成员的结构体目录
			ImageDataDirectory = (UINT_PTR)&((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];


			//导出表地址
			ImageExportDirectory = (ModuleBase + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);

	

			AddressOfNames = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames);


			AddressOfNameOrdinals = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals);
			NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY )ImageExportDirectory)->NumberOfNames;
			IsLoop = 4;

			// loop while we still have imports to find
			while (IsLoop > 0&&NumberOfNames>0)
			{
				// compute the hash values for this function name
				HashValue = MakeHashValue((char *)(ModuleBase + DEREFERENCE_32(AddressOfNames)));

				// if we have found a function we want we get its virtual address
				if (HashValue == LOADLIBRARYA_HASH || 
					HashValue == GETPROCADDRESS_HASH || 
					HashValue == VIRTUALALLOC_HASH ||
					HashValue == EXITTHREAD_HSAH)
				{
					// get the VA for the array of addresses
					AddressOfFunctions = (ModuleBase +
						((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));

					// store this functions VA
					if (HashValue == LOADLIBRARYA_HASH)
						LoadLibraryA = (REFLECTIVELOADER::LPFN_LOADLIBRARYA)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					else if (HashValue == GETPROCADDRESS_HASH)
						GetProcAddress = (REFLECTIVELOADER::LPFN_GETPROCADDRESS)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					else if (HashValue == VIRTUALALLOC_HASH)
						VirtualAlloc = (REFLECTIVELOADER::LPFN_VIRTUALALLOC)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					else if (HashValue == EXITTHREAD_HSAH)
						ExitThread = (REFLECTIVELOADER::LPFN_EXITTHREAD)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));

					// decrement our counter
					IsLoop--;
				}

				// get the next exported function name
				AddressOfNames += sizeof(DWORD);

				// get the next exported function name ordinal
				AddressOfNameOrdinals += sizeof(WORD);

				NumberOfNames--;
			}
		}
		//在目标进程中查询Ntdll动态库
		else if ((DWORD)ModuleHashValue == NTDLLDLL_HASH)
		{
			// get this modules base address
			ModuleBase = (ULONG_PTR)LdrDataTableEntry->Reserved2[0];

			// get the VA of the modules NT Header
			ImageNtHeaders = (ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);


			//有两个成员的结构体目录
			ImageDataDirectory = (UINT_PTR)&((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];


			//导出表地址
			ImageExportDirectory = (ModuleBase + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);


			AddressOfNames = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames);


			AddressOfNameOrdinals = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals);
			NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY )ImageExportDirectory)->NumberOfNames;
			IsLoop = 2;

			// loop while we still have imports to find
			while (IsLoop > 0&&NumberOfNames>0)
			{
				// compute the hash values for this function name
				HashValue = MakeHashValue((char *)(ModuleBase + DEREFERENCE_32(AddressOfNames)));

				// if we have found a function we want we get its virtual address
				if (HashValue == NTFLUSHINSTRUCTIONCACHE_HASH || HashValue == RTLEXITUSERTHREAD_HASH)
				{
					AddressOfFunctions = (ModuleBase +
						((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions);

					// use this functions name ordinal as an index into the array of name pointers
					AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));


					// store this functions VA
					if (HashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
						NtFlushInstructionCache = (REFLECTIVELOADER::LPFN_NTFLUSHINSTRUCTIONCACHE)(ModuleBase 
							+ DEREFERENCE_32(AddressOfFunctions));
					else if (HashValue == RTLEXITUSERTHREAD_HASH)
						RtlExitUserThread = (REFLECTIVELOADER::LPFN_EXITTHREAD)(ModuleBase + 
							DEREFERENCE_32(AddressOfFunctions));

					// decrement our counter
					IsLoop--;
				}

				// get the next exported function name
				AddressOfNames += sizeof(DWORD);

				// get the next exported function name ordinal
				AddressOfNameOrdinals += sizeof(WORD);

				// decrement our # of names counter
				NumberOfNames--;
			}
		}

		// we stop searching when we have found everything we need.
		if (LoadLibraryA && GetProcAddress && VirtualAlloc && ExitThread && NtFlushInstructionCache)
			break;

		// get the next entry

		LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)DEREFERENCE(LdrDataTableEntry);
	}

	// STEP 2: load our image into a new permanent location in memory...

	// get the VA of the NT Header for the PE to be loaded
	ImageNtHeaders = (RemoteBufferData + ((PIMAGE_DOS_HEADER)RemoteBufferData)->e_lfanew);

	// allocate all the memory for the DLL to be loaded into. we can load at any address because we will  
	// relocate the image. Also zeros all memory and marks it as READ, WRITE and EXECUTE to avoid any problems.
	VirtualAddress = (ULONG_PTR)VirtualAlloc(NULL, 
		((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, 
		PAGE_EXECUTE_READWRITE);

	// we must now copy over the headers
	SizeOfHeaders = ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.SizeOfHeaders;


	v1 = (BYTE*)RemoteBufferData;
	v2 = (BYTE*)VirtualAddress;
	while (SizeOfHeaders--)
		*(BYTE *)v2++ = *(BYTE *)v1++;

	// STEP 3.节要使用内存粒度

	// uiValueA = the VA of the first section
	ULONG_PTR ImageSectionHeader = ((ULONG_PTR)&((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader + 
		((PIMAGE_NT_HEADERS)ImageNtHeaders)->FileHeader.SizeOfOptionalHeader);

	// itterate through all sections, loading them into memory.
	NumberOfSections = ((PIMAGE_NT_HEADERS)ImageNtHeaders)->FileHeader.NumberOfSections;
	while (NumberOfSections--)
	{
		// uiValueB is the VA for this section
		SectionVirtualAddress = (VirtualAddress + ((PIMAGE_SECTION_HEADER)ImageSectionHeader)->VirtualAddress);
		


		// uiValueC if the VA for this sections data
		SectionPointerToRawData = (RemoteBufferData + ((PIMAGE_SECTION_HEADER)ImageSectionHeader)->PointerToRawData);

		// copy the section over
		SizeOfRawData = ((PIMAGE_SECTION_HEADER)ImageSectionHeader)->SizeOfRawData;

		while (SizeOfRawData--)
			*(BYTE *)SectionVirtualAddress++ = *(BYTE *)SectionPointerToRawData++;

		// get the VA of the next section
		ImageSectionHeader += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...

	// uiValueB = the address of the import directory
	ImageDataDirectory = (ULONG_PTR)&((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

	// we assume their is an import table to process
	// uiValueC is the first entry in the import table
	ImageImportDescriptor = (VirtualAddress + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);


	while (((PIMAGE_IMPORT_DESCRIPTOR)ImageImportDescriptor)->Name)
	{
		// use LoadLibraryA to load the imported module into memory
		ModuleBase = (ULONG_PTR)LoadLibraryA(
			(LPCSTR)(VirtualAddress + ((PIMAGE_IMPORT_DESCRIPTOR)ImageImportDescriptor)->Name));

		// uiValueD = VA of the OriginalFirstThunk
		OriginalFirstThunk = (VirtualAddress + ((PIMAGE_IMPORT_DESCRIPTOR)ImageImportDescriptor)->OriginalFirstThunk);

		// uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
		FirstThunk = (VirtualAddress + ((PIMAGE_IMPORT_DESCRIPTOR)ImageImportDescriptor)->FirstThunk);

		// itterate through all imported functions, importing by ordinal if no name present
		while (DEREFERENCE(FirstThunk))
		{
			// 索引导入
			if (OriginalFirstThunk && ((PIMAGE_THUNK_DATA)OriginalFirstThunk)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// get the VA of the modules NT Header
				ImageNtHeaders = ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew;
				
				
				ImageDataDirectory = (ULONG_PTR)&((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				
				// get the VA of the export directory
				ImageExportDirectory = (ModuleBase + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);
				// get the VA for the array of addresses
				AddressOfFunctions = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions);

				// use the import ordinal (- export ordinal base) as an index into the array of addresses
				AddressOfFunctions += 
					((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)OriginalFirstThunk)->u1.Ordinal) -
					((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->Base) * sizeof(DWORD));

				// patch in the address for this imported function
				DEREFERENCE(FirstThunk) = (ModuleBase + DEREFERENCE_32(AddressOfFunctions));
			}
			else
			{
				//修正名称导入的函数地址

				// get the VA of this functions import by name struct
				ImageImportByName = (VirtualAddress + DEREFERENCE(OriginalFirstThunk));
				// use GetProcAddress and patch in the address for this imported function
				DEREFERENCE(FirstThunk) = (ULONG_PTR)GetProcAddress((HMODULE)ModuleBase, 
					(LPCSTR)((PIMAGE_IMPORT_BY_NAME)ImageImportByName)->Name);
			}
			// get the next imported function
			FirstThunk += sizeof(ULONG_PTR);
			if (OriginalFirstThunk)
				OriginalFirstThunk += sizeof(ULONG_PTR);
		}
		// get the next import
		ImageImportDescriptor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...

	// calculate the base address delta and perform relocations (even if we load at desired image base)


	ImageNtHeaders = VirtualAddress + ((PIMAGE_DOS_HEADER)VirtualAddress)->e_lfanew;
	Diff = VirtualAddress - ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.ImageBase;


	//代表重定向表的目录
	ImageDataDirectory = (ULONG_PTR)&((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

	// check if their are any relocations present
	if (((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->Size)
	{
		//定位到重定向表
		ImageBaseRelocation = (VirtualAddress + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);

		// and we itterate through all entries...
		while (((PIMAGE_BASE_RELOCATION)ImageBaseRelocation)->SizeOfBlock)
		{
			//重定向表中的word表
			v3 = (VirtualAddress + ((PIMAGE_BASE_RELOCATION)ImageBaseRelocation)->VirtualAddress);

			// uiValueB = number of entries in this relocation block
			ImageBaseRelocationItemCount = 
				(((PIMAGE_BASE_RELOCATION)ImageBaseRelocation)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) 
				/ sizeof(IMAGE_BASE_RELOCATION_ITEM);

			// uiValueD is now the first entry in the current relocation block
			ImageBaseRelocationItem = ImageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION);

			// we itterate through all the entries in the current block...
			while (ImageBaseRelocationItemCount--)
			{
				// perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as required.
				// we dont use a switch statement to avoid the compiler building a jump table
				// which would not be very position independent!
				if (((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Type == IMAGE_REL_BASED_DIR64)
					*(ULONG_PTR *)(v3 + ((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Offset) 
					+= Diff;
				
				else if (((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Type == IMAGE_REL_BASED_HIGHLOW)
					*(DWORD *)(v3 + ((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Offset) 
					+= (DWORD)Diff;

				else if (((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Type == IMAGE_REL_BASED_HIGH)
					*(WORD *)(v3 + ((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Offset) += 
					HIWORD(Diff);
			
				else if (((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Type == IMAGE_REL_BASED_LOW)
					*(WORD *)(v3 + ((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Offset) += LOWORD(Diff);

				// get the next entry in the current relocation block
				ImageBaseRelocationItem += sizeof(IMAGE_BASE_RELOCATION_ITEM);
			}

			// get the next entry in the relocation directory
			ImageBaseRelocation = ImageBaseRelocation + ((PIMAGE_BASE_RELOCATION)ImageBaseRelocation)->SizeOfBlock;
		}
	}

	// STEP 6: call our images entry point

	// uiValueA = the VA of our newly loaded DLL/EXE's entry point
	AddressOfEntryPoint = (VirtualAddress + ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.AddressOfEntryPoint);

	// We must flush the instruction cache to avoid stale code being used which was updated by our relocation processing.
	NtFlushInstructionCache((HANDLE)-1, NULL, 0);

	// call our respective entry point, fudging our hInstance value
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((REFLECTIVELOADER::LPFN_DLLMAIN)AddressOfEntryPoint)((HINSTANCE)VirtualAddress, DLL_PROCESS_ATTACH, ParameterData);

	ImageNtHeaders = VirtualAddress + ((PIMAGE_DOS_HEADER)VirtualAddress)->e_lfanew;
	do
	{
		ImageDataDirectory = (ULONG_PTR)&((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->Size == 0)
			break;

		ImageExportDirectory = (VirtualAddress + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);
		if (((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfNames == 0 || 
			((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfFunctions == 0)
			break;

		
		AddressOfNames = (VirtualAddress + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames);
		AddressOfNameOrdinals = (VirtualAddress + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals);

		NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY )ImageExportDirectory)->NumberOfNames;
		while (NumberOfNames > 0)
		{
			// compute the hash values for this function name
			HashValue = MakeHashValue((char *)(VirtualAddress + DEREFERENCE_32(AddressOfNames)));

			// if we have found a function we want we get its virtual address
			if (HashValue == FunctionHashValue)
			{
				AddressOfFunctions = (VirtualAddress +
					((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions);

				// use this functions name ordinal as an index into the array of name pointers
				AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));
				AddressOfFunctions = VirtualAddress + DEREFERENCE_32(AddressOfFunctions);
				IsOk = TRUE;
				break;
			}

			// get the next exported function name
			AddressOfNames += sizeof(DWORD);

			// get the next exported function name ordinal
			AddressOfNameOrdinals += sizeof(WORD);

			// decrement our # of names counter
			NumberOfNames--;
		}
	
		if (IsOk == FALSE)
			break;

		if (!((REFLECTIVELOADER::LPFN_MYFUNCTION)AddressOfFunctions)(UserData, UserDataLength))
			break;

		ExitCode = 0;
	} while (0);

	// We're done, exit thread
	if (RtlExitUserThread)
		RtlExitUserThread(ExitCode);
	else
		ExitThread(ExitCode);
	
}



extern "C"
__declspec(dllexport)   
BOOL
MyFunction(LPVOID UserData, DWORD UserDataLength)
{
	LPSTR v1 = (LPSTR)malloc(32 + UserDataLength);
	sprintf_s(v1, 32 + UserDataLength, "HelloShine from MyFunction: %s!", UserData);
	MessageBoxA(NULL, v1, (LPCSTR)UserData, MB_OK);
	free(v1);
	return TRUE;
}
