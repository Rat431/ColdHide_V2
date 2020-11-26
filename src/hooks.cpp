/*
	Copyright (c) 2020 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#include "hooks.h"
#include "Defs.h"
#include <vector>
#include <versionhelpers.h>
#include <tlhelp32.h>

#ifdef _WIN64
#define VALID_MACHINE IMAGE_FILE_MACHINE_AMD64
#else
#define VALID_MACHINE IMAGE_FILE_MACHINE_I386
#endif

// var
static char ColdHidepath[MAX_PATH] = { 0 };

namespace Hooks_Informastion
{
	HMODULE hNtDll = NULL;
	HMODULE hKernel = NULL;
	HMODULE hKernel32 = NULL;
	void * KIUEDRPage = NULL;
	DWORD CurrentProcessID = NULL;
	ULONG_PTR FPPID = NULL;

	// PEB.
	void * PEB_BeingDebuggedP = NULL;
	int32_t PEB_BeingDebuggedID = NULL;

	void * PEB_NtGlobalFlagP = NULL;
	int32_t PEB_NtGlobalFlagID = NULL;

	// HeapFlags
	void * FlagsHeapFlagsP = NULL;
	int32_t FlagsHeapFlagsID = NULL;

	// Some ntdll apis
	void * Nt_QueryProcessP = NULL;
	int32_t Nt_QueryProcessID = NULL;

	void * Nt_QuerySystemP = NULL;
	int32_t Nt_QuerySystemID = NULL;

	void * Nt_SetThreadInformationP = NULL;
	int32_t Nt_SetThreadInformationID = NULL;

	void * Nt_CloseP = NULL;
	int32_t Nt_CloseID = NULL;

	void * Nt_QueryObjectP = NULL;
	int32_t Nt_QueryObjectID = NULL;

	void * Nt_NtGetContextThreadP = NULL;
	int32_t Nt_NtGetContextThreadID = NULL;

	void * Nt_NtSetContextThreadP = NULL;
	int32_t Nt_NtSetContextThreadID = NULL;

	void * Nt_ContinueP = NULL;
	int32_t Nt_ContinueID = NULL;

	void * Nt_CreateThreadExP = NULL;
	int32_t Nt_CreateThreadExID = NULL;

	void * Nt_ExceptionDispatcherP = NULL;
	int32_t Nt_ExceptionDispatcherID = NULL;

	void * Nt_SetInformationProcessP = NULL;
	int32_t Nt_SetInformationProcessID = NULL;

	void * Nt_YieldExecutionP = NULL;
	int32_t Nt_YieldExecutionID = NULL;

	void * Nt_SetDebugFilterStateP = NULL;
	int32_t Nt_SetDebugFilterStateID = NULL;

	void * Kernel32_Process32FirstWP = NULL;
	int32_t Kernel32_Process32FirstWID = NULL;

	void * Kernel32_Process32NextWP = NULL;
	int32_t Kernel32_Process32NextWID = NULL;

	void * Kernel32_GetTickCountP = NULL;
	int32_t Kernel32_GetTickCountID = NULL;

	void * Kernel32_GetTickCount64P = NULL;
	int32_t Kernel32_GetTickCount64ID = NULL;
}

namespace Hooks_Config
{
	// Hide PEB.
	bool HideWholePEB = true;
	bool PEB_BeingDebugged = false;
	bool PEB_NtGlobalFlag = false;

	// HeapFlags
	bool HeapFlags = false;

	// DRx
	bool HideWholeDRx = true;
	bool FakeContextEmulation = false;

	bool DRx_ThreadContextRead = false;
	bool DRx_ThreadContextWrite = false;
	bool Nt_Continue = false;
	bool Nt_KiUserExceptionDispatcher = false;

	// Anti attach
	bool Anti_Anti_Attach = false;

	// Some ntdll apis
	bool Nt_QueryProcess = true;
	bool Nt_QuerySystem = true;
	bool Nt_SetThreadInformation = true;
	bool Nt_Close = true;
	bool Nt_QueryObject = true;
	bool Nt_CreateThreadEx = true;
	bool Nt_SetInformationProcess = true;
	bool Nt_YieldExecution = true;
	bool Nt_SetDebugFilterState = true;

	bool Kernel32_Process32First = true;
	bool Kernel32_Process32Next = true;
	bool Kernel32_GetTickCount = true;
	bool Kernel32_GetTickCount64 = true;
}

namespace Hooks
{
	static void HidePEB()
	{
		void * PEB_BaseAddress = nullptr;
		void * _HeapAddress = nullptr;

		// Get PEB Address by the offset, or you can even call NtQueryInformationProcess.
		PEB_BaseAddress = (void *) GetPebFunction();

		if (PEB_BaseAddress)
		{
			// Check if we should patch the flags first.
			if (Hooks_Config::PEB_BeingDebugged)
			{
				Hooks_Informastion::PEB_BeingDebuggedP = (void *) ((ULONG_PTR) PEB_BaseAddress + PEB_BeingDebuggedOffset);
				*(BYTE *) Hooks_Informastion::PEB_BeingDebuggedP = 0;
			}
			if (Hooks_Config::PEB_NtGlobalFlag)
			{
				Hooks_Informastion::PEB_NtGlobalFlagP = (void *) ((ULONG_PTR) PEB_BaseAddress + PEB_NtGlobalFlagOffset);
				*(BYTE *) Hooks_Informastion::PEB_NtGlobalFlagP = 0;
			}
			if (Hooks_Config::HeapFlags)
			{
				// Get Process heap base address
				memcpy( &_HeapAddress, (void *) ((ULONG_PTR) PEB_BaseAddress + HeapPEB_Offset), MAX_ADDRESS_SIZE );

				if (_HeapAddress)
				{
					// Check if the current Windows OS is Windows Vista or greater as different force flags and heap flags offsets in older versions.
					if (IsWindowsVistaOrGreater())
					{
						// Check if HEAP_GROWABLE flag is not setted, if not, we set it
						if (!(*(DWORD *) ((ULONG_PTR) _HeapAddress + HeapFlagsBaseWinHigher) & HEAP_GROWABLE))
						{
							*(DWORD *) ((ULONG_PTR) _HeapAddress + HeapFlagsBaseWinHigher) |= HEAP_GROWABLE;
						}
						*(DWORD *) ((ULONG_PTR) _HeapAddress + HeapForceFlagsBaseWinHigher) = 0;
					}
					else
					{
						// Check if HEAP_GROWABLE flag is not setted, if not, we set it
						if (!(*(DWORD *) ((ULONG_PTR) _HeapAddress + HeapFlagsBaseWinLower) & HEAP_GROWABLE))
						{
							*(DWORD *) ((ULONG_PTR) _HeapAddress + HeapFlagsBaseWinLower) |= HEAP_GROWABLE;
						}
						*(DWORD *) ((ULONG_PTR) _HeapAddress + HeapForceFlagsBaseWinLower) = 0;
					}
				}
			}
		}
	}

	static void HideDRx()
	{
		Hooks_Informastion::Nt_NtGetContextThreadP = GetProcAddress( Hooks_Informastion::hNtDll, "NtGetContextThread" );
		Hooks_Informastion::Nt_NtSetContextThreadP = GetProcAddress( Hooks_Informastion::hNtDll, "NtSetContextThread" );

		if (Hooks_Informastion::Nt_NtGetContextThreadP)
		{
			if (Hooks_Config::DRx_ThreadContextRead)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_NtGetContextThreadID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_NtGetContextThreadP, Hook_emu::__NtGetContextThread, &ErrorCode );

				if (Hooks_Informastion::Nt_NtGetContextThreadID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_NtGetContextThreadID, &ErrorCode );
					Hooks_Informastion::Nt_NtGetContextThreadP = HookDataS->OriginalF;
				}
			}
		}
		if (Hooks_Informastion::Nt_NtSetContextThreadP)
		{
			if (Hooks_Config::DRx_ThreadContextWrite)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_NtSetContextThreadID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_NtSetContextThreadP, Hook_emu::__NtSetContextThread, &ErrorCode );

				if (Hooks_Informastion::Nt_NtSetContextThreadID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_NtSetContextThreadID, &ErrorCode );
					Hooks_Informastion::Nt_NtSetContextThreadP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideProcessInformations()
	{
		Hooks_Informastion::Nt_QueryProcessP = GetProcAddress( Hooks_Informastion::hNtDll, "NtQueryInformationProcess" );

		if (Hooks_Informastion::Nt_QueryProcessP)
		{
			if (Hooks_Config::Nt_QueryProcess)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_QueryProcessID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_QueryProcessP, Hook_emu::__NtQueryInformationProcess, &ErrorCode );

				if (Hooks_Informastion::Nt_QueryProcessID > 0 && ErrorCode == 0)
				{
					if (ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_QueryProcessID, &ErrorCode ))
					{
						Hooks_Informastion::Nt_QueryProcessP = HookDataS->OriginalF;
					}
				}
			}
		}
	}
	static void HideSetInformationThread()
	{
		Hooks_Informastion::Nt_SetThreadInformationP = GetProcAddress( Hooks_Informastion::hNtDll, "NtSetInformationThread" );

		if (Hooks_Informastion::Nt_SetThreadInformationP)
		{
			if (Hooks_Config::Nt_SetThreadInformation)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_SetThreadInformationID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_SetThreadInformationP, Hook_emu::__NtSetInformationThread, &ErrorCode );

				if (Hooks_Informastion::Nt_SetThreadInformationID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_SetThreadInformationID, &ErrorCode );
					Hooks_Informastion::Nt_SetThreadInformationP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideQuerySystemInformation()
	{
		Hooks_Informastion::Nt_QuerySystemP = GetProcAddress( Hooks_Informastion::hNtDll, "NtQuerySystemInformation" );

		if (Hooks_Informastion::Nt_QuerySystemP)
		{
			if (Hooks_Config::Nt_QuerySystem)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_QuerySystemID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_QuerySystemP, Hook_emu::__NtQuerySystemInformation, &ErrorCode );

				if (Hooks_Informastion::Nt_QuerySystemID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_QuerySystemID, &ErrorCode );
					Hooks_Informastion::Nt_QuerySystemP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideCloseHandle()
	{
		Hooks_Informastion::Nt_CloseP = GetProcAddress( Hooks_Informastion::hNtDll, "NtClose" );

		if (Hooks_Informastion::Nt_CloseP)
		{
			if (Hooks_Config::Nt_Close)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_CloseID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_CloseP, Hook_emu::__NtClose, &ErrorCode );

				if (Hooks_Informastion::Nt_CloseID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_CloseID, &ErrorCode );
					Hooks_Informastion::Nt_CloseP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideQueryObject()
	{
		Hooks_Informastion::Nt_QueryObjectP = GetProcAddress( Hooks_Informastion::hNtDll, "NtQueryObject" );

		if (Hooks_Informastion::Nt_QueryObjectP)
		{
			if (Hooks_Config::Nt_QueryObject)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_QueryObjectID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_QueryObjectP, Hook_emu::__NtQueryObject, &ErrorCode );

				if (Hooks_Informastion::Nt_QueryObjectID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_QueryObjectID, &ErrorCode );
					Hooks_Informastion::Nt_QueryObjectP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideSetInformationProcess()
	{
		Hooks_Informastion::Nt_SetInformationProcessP = GetProcAddress( Hooks_Informastion::hNtDll, "NtSetInformationProcess" );

		if (Hooks_Informastion::Nt_SetInformationProcessP)
		{
			if (Hooks_Config::Nt_SetInformationProcess)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_SetInformationProcessID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_SetInformationProcessP, Hook_emu::__NtSetInformationProcess, &ErrorCode );

				if (Hooks_Informastion::Nt_SetInformationProcessID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_SetInformationProcessID, &ErrorCode );
					Hooks_Informastion::Nt_SetInformationProcessP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideNtContinue()
	{
		Hooks_Informastion::Nt_ContinueP = GetProcAddress( Hooks_Informastion::hNtDll, "NtContinue" );

		if (Hooks_Informastion::Nt_ContinueP)
		{
			if (Hooks_Config::Nt_Continue)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_ContinueID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_ContinueP, Hook_emu::__NtContinue, &ErrorCode );

				if (Hooks_Informastion::Nt_ContinueID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_ContinueID, &ErrorCode );
					Hooks_Informastion::Nt_ContinueP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideCreateThreadEx()
	{
		Hooks_Informastion::Nt_CreateThreadExP = GetProcAddress( Hooks_Informastion::hNtDll, "NtCreateThreadEx" );

		if (Hooks_Informastion::Nt_CreateThreadExP)
		{
			if (Hooks_Config::Nt_CreateThreadEx)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_CreateThreadExID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_CreateThreadExP, Hook_emu::__NtCreateThreadEx, &ErrorCode );

				if (Hooks_Informastion::Nt_CreateThreadExID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_CreateThreadExID, &ErrorCode );
					Hooks_Informastion::Nt_CreateThreadExP = HookDataS->OriginalF;
				}
			}
		}
	}
	static BYTE x64KIUEDHook[25] = { 0x48, 0x89, 0xE1, 0x48, 0x81, 0xC1, 0xF0, 0x04, 0x00, 0x00, 0x48, 0x89,
		0xE2, 0xFF, 0x15, 0x0E, 0x00, 0x00, 0x00, 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
	static void HideExceptionDispatcher()
	{
		Hooks_Informastion::Nt_ExceptionDispatcherP = GetProcAddress( Hooks_Informastion::hNtDll, "KiUserExceptionDispatcher" );

		if (Hooks_Informastion::Nt_ExceptionDispatcherP)
		{
			if (Hooks_Config::Nt_KiUserExceptionDispatcher)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;
				void * TempPointer = nullptr;
				bool IsRunning64Bit = ColdHook_Service::Is64BitProcess();

				if (IsRunning64Bit)
				{
					// Allocate a page 
					Hooks_Informastion::KIUEDRPage = VirtualAlloc( nullptr, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE );
					TempPointer = Hooks_Informastion::KIUEDRPage;
				}
				else
				{
					TempPointer = Hook_emu::__RKiUserExceptionDispatcher;
				}
				if (TempPointer)
				{
					Hooks_Informastion::Nt_ExceptionDispatcherID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
						Hooks_Informastion::Nt_ExceptionDispatcherP, TempPointer, &ErrorCode );

					if (Hooks_Informastion::Nt_ExceptionDispatcherID > 0 && ErrorCode == 0)
					{
						ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_ExceptionDispatcherID, &ErrorCode );
						Hooks_Informastion::Nt_ExceptionDispatcherP = HookDataS->OriginalF;

						if (IsRunning64Bit)
						{
							memcpy( TempPointer, x64KIUEDHook, sizeof( x64KIUEDHook ) );
							*(void **) ((ULONG_PTR) TempPointer + sizeof( x64KIUEDHook )) = Hooks_Informastion::Nt_ExceptionDispatcherP;
							*(void **) ((ULONG_PTR) TempPointer + sizeof( x64KIUEDHook ) + sizeof( void * )) = Hook_emu::__KiUserExceptionDispatcher;
						}
					}
				}
			}
		}
	}
	static void HideYieldExecution()
	{
		Hooks_Informastion::Nt_YieldExecutionP = GetProcAddress( Hooks_Informastion::hNtDll, "NtYieldExecution" );

		if (Hooks_Informastion::Nt_YieldExecutionP)
		{
			if (Hooks_Config::Nt_YieldExecution)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_YieldExecutionID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_YieldExecutionP, Hook_emu::__NtYieldExecution, &ErrorCode );

				if (Hooks_Informastion::Nt_YieldExecutionID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_YieldExecutionID, &ErrorCode );
					Hooks_Informastion::Nt_YieldExecutionP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideSetDebugFilterState()
	{
		Hooks_Informastion::Nt_SetDebugFilterStateP = GetProcAddress( Hooks_Informastion::hNtDll, "NtSetDebugFilterState" );

		if (Hooks_Informastion::Nt_SetDebugFilterStateP)
		{
			if (Hooks_Config::Nt_SetDebugFilterState)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Nt_SetDebugFilterStateID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Nt_SetDebugFilterStateP, Hook_emu::__NtSetDebugFilterState, &ErrorCode );

				if (Hooks_Informastion::Nt_SetDebugFilterStateID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Nt_SetDebugFilterStateID, &ErrorCode );
					Hooks_Informastion::Nt_SetDebugFilterStateP = HookDataS->OriginalF;
				}
			}
		}
	}
	static bool RetrieveSystemDirectory( char * OutPut )
	{
		#ifdef _WIN64
		GetSystemDirectoryA( OutPut, MAX_PATH );
		#else
		GetSystemWow64DirectoryA( OutPut, MAX_PATH );
		if (GetLastError() == ERROR_CALL_NOT_IMPLEMENTED)
		{
			GetSystemDirectoryA( OutPut, MAX_PATH );
		}
		#endif
		return true;
	}
	static bool IsAddressSection( ULONG_PTR address, ULONG_PTR Baseaddress, IMAGE_SECTION_HEADER * pSHeader, IMAGE_NT_HEADERS * ntheader, void ** OutSBaseAddress,
		SIZE_T * OutSSize )
	{
		for (int i = 0; i < ntheader->FileHeader.NumberOfSections; i++)
		{
			if ((pSHeader->VirtualAddress <= (address - Baseaddress)) && ((address - Baseaddress) < (pSHeader->VirtualAddress + pSHeader->Misc.VirtualSize)))
			{
				*OutSBaseAddress = (void *) ((ULONG_PTR) Baseaddress + pSHeader->VirtualAddress);
				*OutSSize = pSHeader->Misc.VirtualSize;
				return true;
			}
			pSHeader++;
		}
		return false;
	}
	static size_t ConvertRvaToOffset( ULONG_PTR address, ULONG_PTR Baseaddress, IMAGE_SECTION_HEADER * pSHeader, IMAGE_NT_HEADERS * ntheader )
	{
		for (int i = 0; i < ntheader->FileHeader.NumberOfSections; i++)
		{
			if ((pSHeader->VirtualAddress <= (address - Baseaddress)) && ((address - Baseaddress) < (pSHeader->VirtualAddress + pSHeader->Misc.VirtualSize)))
			{
				return (address - Baseaddress - pSHeader->VirtualAddress) + (pSHeader->PointerToRawData);
			}
			pSHeader++;
		}
		return NULL;
	}
	static bool IsAddressPresent( void ** Buffer, void * Address, size_t size )
	{
		void ** Start = Buffer;
		for (size_t i = 0; i < size; i++, Start++)
		{
			if (*Start == Address)
			{
				return true;
			}
		}
		return false;
	}
	static CHAR SystemDirectory[MAX_PATH] = { 0 };
	static void HideAntiAntiAttach()
	{
		if (Hooks_Config::Anti_Anti_Attach)
		{
			// Vars
			void * Page = nullptr;
			void ** ExportsPage = nullptr;
			void ** ExportsPageDbg = nullptr;
			void * OriginalMappedNtdll = nullptr;

			size_t ExportsFunctions = 0;
			size_t fileSize = 0;

			HANDLE FileP = 0;

			// Check if the variable is empty 
			if (SystemDirectory[0] == 0)
			{
				RetrieveSystemDirectory( SystemDirectory );
				lstrcatA( SystemDirectory, "\\ntdll.dll" );
			}

			// Read the file
			FileP = CreateFileA( SystemDirectory, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
			if (FileP != INVALID_HANDLE_VALUE)
			{
				// Get file size
				fileSize = GetFileSize( FileP, NULL );

				Page = VirtualAlloc( nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
				if (Page)
				{
					// Read the file and parse headers later
					DWORD READ;
					if (!ReadFile( FileP, Page, fileSize, &READ, NULL ))
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}

					// Headers
					auto pDosHeader = (IMAGE_DOS_HEADER *) Hooks_Informastion::hNtDll;
					if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}
					auto pNtHeader = (IMAGE_NT_HEADERS *) ((ULONG_PTR) Hooks_Informastion::hNtDll + pDosHeader->e_lfanew);
					if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}
					if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size <= 0)
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}
					if (pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress <= 0)
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}

					auto pDosHeaderFile = (IMAGE_DOS_HEADER *) Page;
					if (pDosHeaderFile->e_magic != IMAGE_DOS_SIGNATURE)
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}
					auto pNtHeaderFile = (IMAGE_NT_HEADERS *) ((ULONG_PTR) Page + pDosHeaderFile->e_lfanew);
					if (pNtHeaderFile->Signature != IMAGE_NT_SIGNATURE)
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}
					if (pNtHeaderFile->FileHeader.Machine != VALID_MACHINE)
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}

					// Map 
					OriginalMappedNtdll = VirtualAlloc( nullptr, pNtHeaderFile->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
					if (!OriginalMappedNtdll)
					{
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}

					memcpy( OriginalMappedNtdll, Page, pNtHeaderFile->OptionalHeader.SizeOfHeaders );
					auto pSecHeader = IMAGE_FIRST_SECTION( pNtHeaderFile );
					for (int i = 0; i < pNtHeaderFile->FileHeader.NumberOfSections; i++, pSecHeader++)
					{
						if (pSecHeader->SizeOfRawData)
						{
							memcpy( (void *) ((ULONG_PTR) OriginalMappedNtdll + pSecHeader->VirtualAddress), (void *) ((ULONG_PTR) Page + pSecHeader->PointerToRawData),
								pSecHeader->SizeOfRawData );
						}
					}

					auto pExports = (IMAGE_EXPORT_DIRECTORY *) ((ULONG_PTR) Hooks_Informastion::hNtDll + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

					ExportsFunctions = (sizeof( void * ) * pExports->NumberOfFunctions) + 0x100;
					ExportsPage = (void **) VirtualAlloc( 0, ExportsFunctions, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
					if (!ExportsPage)
					{
						VirtualFree( OriginalMappedNtdll, 0, MEM_RELEASE );
						VirtualFree( Page, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}

					memset( ExportsPage, ExportsFunctions, 0 );

					// Store exports pointers
					size_t DbgFunctionsCount = 0;
					DWORD * pExpNames = (DWORD *) ((ULONG_PTR) Hooks_Informastion::hNtDll + pExports->AddressOfNames);
					WORD * pOrdinalName = (WORD *) ((ULONG_PTR) Hooks_Informastion::hNtDll + pExports->AddressOfNameOrdinals);
					DWORD * pFunction = (DWORD *) ((ULONG_PTR) Hooks_Informastion::hNtDll + pExports->AddressOfFunctions);

					for (unsigned int i = 0; i < pExports->NumberOfFunctions; i++)
					{
						for (unsigned int b = 0; b < pExports->NumberOfNames; b++)
						{
							if (pOrdinalName[b] == i)
							{
								auto pFunctionName = (PCHAR) ((ULONG_PTR) Hooks_Informastion::hNtDll + pExpNames[b]);
								if (pFunctionName)
								{
									if (strncmp( pFunctionName, "Dbg", 3 ) == 0)
									{
										DbgFunctionsCount++;
									}
								}
							}
						}
						ExportsPage[i] = (void *) ((ULONG_PTR) Hooks_Informastion::hNtDll + pFunction[i]);
					}

					ExportsPageDbg = (void **) VirtualAlloc( nullptr, (sizeof( void * ) * DbgFunctionsCount) + 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
					if (!ExportsPageDbg)
					{
						VirtualFree( OriginalMappedNtdll, 0, MEM_RELEASE );
						VirtualFree( Page, 0, MEM_RELEASE );
						VirtualFree( ExportsPage, 0, MEM_RELEASE );
						CloseHandle( FileP );
						return;
					}

					memset( ExportsPageDbg, (sizeof( void * ) * DbgFunctionsCount) + 0x100, 0 );

					// Now store target functions that we must restore
					void ** ExportsPageDbgFLoop = ExportsPageDbg;
					for (unsigned int i = 0; i < pExports->NumberOfNames; i++)
					{
						auto pFunctionName = (PCHAR) ((ULONG_PTR) Hooks_Informastion::hNtDll + pExpNames[i]);
						if (pFunctionName)
						{
							if (strncmp( pFunctionName, "Dbg", 3 ) == 0)
							{
								*ExportsPageDbgFLoop = GetProcAddress( Hooks_Informastion::hNtDll, pFunctionName );
								ExportsPageDbgFLoop++;
							}
						}
					}

					// Restore
					for (size_t i = 0; i < DbgFunctionsCount; i++)
					{
						for (size_t m = 0; m < 0x100; m++)
						{
							PBYTE TargetRestoreAddr = (PBYTE) ((ULONG_PTR) ExportsPageDbg[i] + m);
							DWORD CurrRVa;
							PBYTE pOrgByte;
							DWORD OLD;
							bool Break = false;
							if (m != 0)
							{
								// If we reach another export function then break.
								for (unsigned int x = 0; x < pExports->NumberOfFunctions; x++)
								{
									if (ExportsPage[x] == (void *) TargetRestoreAddr)
									{
										Break = true;
										break;
									}
								}
							}
							if (Break)
							{
								break;
							}
							CurrRVa = (DWORD) ((ULONG_PTR) TargetRestoreAddr - (ULONG_PTR) Hooks_Informastion::hNtDll);
							pOrgByte = (PBYTE) ((ULONG_PTR) OriginalMappedNtdll + CurrRVa);
							if (VirtualProtect( TargetRestoreAddr, sizeof( BYTE ), PAGE_EXECUTE_READWRITE, &OLD ))
							{
								*TargetRestoreAddr = *pOrgByte;
								VirtualProtect( TargetRestoreAddr, sizeof( BYTE ), OLD, &OLD );
							}
						}
					}

					// Free
					VirtualFree( OriginalMappedNtdll, 0, MEM_RELEASE );
					VirtualFree( Page, 0, MEM_RELEASE );
					VirtualFree( ExportsPage, 0, MEM_RELEASE );
					VirtualFree( ExportsPageDbg, 0, MEM_RELEASE );
				}
				CloseHandle( FileP );
			}
		}
	}

	static void HideProcess32First()
	{
		Hooks_Informastion::Kernel32_Process32FirstWP = GetProcAddress( Hooks_Informastion::hKernel32, "Process32FirstW" );

		if (Hooks_Config::Kernel32_Process32First)
		{
			if (Hooks_Informastion::Kernel32_Process32FirstWP)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Kernel32_Process32FirstWID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Kernel32_Process32FirstWP, Hook_emu::__Process32FirstW, &ErrorCode );

				if (Hooks_Informastion::Kernel32_Process32FirstWID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Kernel32_Process32FirstWID, &ErrorCode );
					Hooks_Informastion::Kernel32_Process32FirstWP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideProcess32Next()
	{
		Hooks_Informastion::Kernel32_Process32NextWP = GetProcAddress( Hooks_Informastion::hKernel32, "Process32NextW" );

		if (Hooks_Config::Kernel32_Process32Next)
		{
			if (Hooks_Informastion::Kernel32_Process32NextWP)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Kernel32_Process32NextWID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, true,
					Hooks_Informastion::Kernel32_Process32NextWP, Hook_emu::__Process32NextW, &ErrorCode );

				if (Hooks_Informastion::Kernel32_Process32NextWID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Kernel32_Process32NextWID, &ErrorCode );
					Hooks_Informastion::Kernel32_Process32NextWP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideGetTickCount()
	{
		Hooks_Informastion::Kernel32_GetTickCountP = GetProcAddress( Hooks_Informastion::hKernel32, "GetTickCount" );

		if (Hooks_Config::Kernel32_GetTickCount)
		{
			if (Hooks_Informastion::Kernel32_GetTickCountP)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Kernel32_GetTickCountID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, false,
					Hooks_Informastion::Kernel32_GetTickCountP, Hook_emu::__GetTickCount, &ErrorCode );

				if (Hooks_Informastion::Kernel32_GetTickCountID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Kernel32_GetTickCountID, &ErrorCode );
					Hooks_Informastion::Kernel32_GetTickCountP = HookDataS->OriginalF;
				}
			}
		}
	}
	static void HideGetTickCount64()
	{
		Hooks_Informastion::Kernel32_GetTickCount64P = GetProcAddress( Hooks_Informastion::hKernel32, "GetTickCount64" );

		if (Hooks_Config::Kernel32_GetTickCount64)
		{
			if (Hooks_Informastion::Kernel32_GetTickCount64P)
			{
				// Hook
				Hook_Info * HookDataS;
				int32_t ErrorCode = 0;

				Hooks_Informastion::Kernel32_GetTickCount64ID = ColdHook_Service::InitFunctionHookByAddress( &HookDataS, false,
					Hooks_Informastion::Kernel32_GetTickCount64P, Hook_emu::__GetTickCount64, &ErrorCode );

				if (Hooks_Informastion::Kernel32_GetTickCount64ID > 0 && ErrorCode == 0)
				{
					ColdHook_Service::ServiceRegisterHookInformation( HookDataS, Hooks_Informastion::Kernel32_GetTickCount64ID, &ErrorCode );
					Hooks_Informastion::Kernel32_GetTickCount64P = HookDataS->OriginalF;
				}
			}
		}
	}
}
namespace Hooks_Manager
{
	// Init and ShutDown
	static bool IsInited = false;
	void Init( HMODULE hMain )
	{
		if (!IsInited)
		{
			// ReadIniConfiguration first
			Hooks_Manager::InitInternalPath( hMain );
			Hooks_Manager::ReadIni();

			// Initialiizzation
			if (ColdHook_Service::ServiceGlobalInit( nullptr ))
			{
				Hooks_Informastion::hNtDll = GetModuleHandleA( "ntdll.dll" );
				Hooks_Informastion::hKernel = GetModuleHandleA( "kernelbase.dll" );

				if (Hooks_Informastion::hKernel == nullptr)
				{
					Hooks_Informastion::hKernel = GetModuleHandleA( "kernel32.dll" );
				}

				Hooks_Informastion::hKernel32 = GetModuleHandleA( "kernel32.dll" );

				// Store the current PID
				Hooks_Informastion::CurrentProcessID = GetCurrentProcessId();
				Hooks_Manager::GetExplorerPID();

				// Call hooking functions
				Hooks::HideAntiAntiAttach();

				Hooks::HideProcessInformations();
				Hooks::HideCloseHandle();
				Hooks::HideDRx();
				Hooks::HidePEB();
				Hooks::HideQueryObject();
				Hooks::HideQuerySystemInformation();
				Hooks::HideSetInformationThread();
				Hooks::HideSetInformationProcess();
				Hooks::HideNtContinue();
				Hooks::HideCreateThreadEx();
				Hooks::HideExceptionDispatcher();
				Hooks::HideYieldExecution();
				Hooks::HideSetDebugFilterState();
				Hooks::HideProcess32First();
				Hooks::HideProcess32Next();
				Hooks::HideGetTickCount64();
				Hooks::HideGetTickCount();

				Hook_emu::InitHookFunctionsVars();
				IsInited = true;
			}
		}
	}
	void ShutDown()
	{
		return;
	}

	// Configuration
	static void ReadIni()
	{
		char INI[MAX_PATH] = { 0 };
		strcpy( INI, ColdHidepath );
		strcat( INI, "ColdHide.ini" );

		Hooks_Config::HideWholePEB = GetPrivateProfileIntA( "PEB_Hook", "HideWholePEB", true, INI ) != FALSE;

		if (!Hooks_Config::HideWholePEB)
		{
			Hooks_Config::PEB_BeingDebugged = GetPrivateProfileIntA( "PEB_Hook", "BeingDebugged", true, INI ) != FALSE;
			Hooks_Config::PEB_NtGlobalFlag = GetPrivateProfileIntA( "PEB_Hook", "NtGlobalFlag", true, INI ) != FALSE;
			Hooks_Config::HeapFlags = GetPrivateProfileIntA( "PEB_Hook", "HeapFlags", true, INI ) != FALSE;
		}
		else
		{
			Hooks_Config::HideWholePEB = false;
			Hooks_Config::PEB_BeingDebugged = true;
			Hooks_Config::PEB_NtGlobalFlag = true;
			Hooks_Config::HeapFlags = true;
		}
		Hooks_Config::HideWholeDRx = GetPrivateProfileIntA( "Nt_DRx", "HideWholeDRx", true, INI ) != FALSE;
		Hooks_Config::FakeContextEmulation = GetPrivateProfileIntA( "Nt_DRx", "FakeContextEmulation", true, INI ) != FALSE;
		if (!Hooks_Config::HideWholeDRx)
		{
			Hooks_Config::DRx_ThreadContextRead = GetPrivateProfileIntA( "Nt_DRx", "NtGetContextThread", true, INI ) != FALSE;
			Hooks_Config::DRx_ThreadContextWrite = GetPrivateProfileIntA( "Nt_DRx", "NtSetContextThread", true, INI ) != FALSE;
			Hooks_Config::Nt_Continue = GetPrivateProfileIntA( "Nt_DRx", "NtContinue", true, INI ) != FALSE;
			Hooks_Config::Nt_KiUserExceptionDispatcher = GetPrivateProfileIntA( "Nt_DRx", "KiUserExceptionDispatcher", true, INI ) != FALSE;
		}
		else
		{
			Hooks_Config::HideWholeDRx = false;
			Hooks_Config::DRx_ThreadContextRead = true;
			Hooks_Config::DRx_ThreadContextWrite = true;
			Hooks_Config::Nt_Continue = true;
			Hooks_Config::Nt_KiUserExceptionDispatcher = true;
		}
		Hooks_Config::Anti_Anti_Attach = GetPrivateProfileIntA( "Additional", "Anti_Anti_Attach", false, INI ) != FALSE;

		Hooks_Config::Nt_QueryProcess = GetPrivateProfileIntA( "NTAPIs", "NtQueryInformationProcess", true, INI ) != FALSE;
		Hooks_Config::Nt_QuerySystem = GetPrivateProfileIntA( "NTAPIs", "NtQuerySystemInformation", true, INI ) != FALSE;
		Hooks_Config::Nt_SetThreadInformation = GetPrivateProfileIntA( "NTAPIs", "NtSetInformationThread", true, INI ) != FALSE;
		Hooks_Config::Nt_Close = GetPrivateProfileIntA( "NTAPIs", "NtClose", true, INI ) != FALSE;
		Hooks_Config::Nt_QueryObject = GetPrivateProfileIntA( "NTAPIs", "NtQueryObject", true, INI ) != FALSE;
		Hooks_Config::Nt_CreateThreadEx = GetPrivateProfileIntA( "NTAPIs", "NtCreateThreadEx", true, INI ) != FALSE;
		Hooks_Config::Nt_SetInformationProcess = GetPrivateProfileIntA( "NTAPIs", "NtSetInformationProcess", true, INI ) != FALSE;
		Hooks_Config::Nt_YieldExecution = GetPrivateProfileIntA( "NTAPIs", "NtYieldExecution", true, INI ) != FALSE;
		Hooks_Config::Nt_SetDebugFilterState = GetPrivateProfileIntA( "NTAPIs", "NtSetDebugFilterState", true, INI ) != FALSE;

		Hooks_Config::Kernel32_Process32First = GetPrivateProfileIntA( "WinAPIs", "Process32First", true, INI ) != FALSE;
		Hooks_Config::Kernel32_Process32Next = GetPrivateProfileIntA( "WinAPIs", "Process32Next", true, INI ) != FALSE;
		Hooks_Config::Kernel32_GetTickCount = GetPrivateProfileIntA( "WinAPIs", "GetTickCount", true, INI ) != FALSE;
		Hooks_Config::Kernel32_GetTickCount64 = GetPrivateProfileIntA( "WinAPIs", "GetTickCount64", true, INI ) != FALSE;
	}
	static void InitInternalPath( HMODULE hMain )
	{
		size_t Length = GetModuleFileNameA( hMain, ColdHidepath, sizeof( ColdHidepath ) );
		if (Length)
		{
			for (size_t i = Length; i > 0; i--)
			{
				if (ColdHidepath[i] == '\\' || ColdHidepath[i] == '/')
				{
					memset( &ColdHidepath[i + 1], 0, Length - (i + 1) );
					break;
				}
			}
		}
	}
	void GetExplorerPID()
	{
		// Get fake PID.
		HANDLE hProcessSnap = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );

		if (hProcessSnap != INVALID_HANDLE_VALUE)
		{
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof( PROCESSENTRY32 );

			if (Process32First( hProcessSnap, &pe32 ))
			{
				do
				{
					if (lstrcmp( pe32.szExeFile, L"explorer.exe" ) == 0)
					{
						Hooks_Informastion::FPPID = pe32.th32ProcessID;
						break;
					}
				} while (Process32Next( hProcessSnap, &pe32 ) == TRUE);
				CloseHandle( hProcessSnap );
			}
		}
	}
	static std::vector<DWORD> ThreadDataID;
	size_t GetOffsetByThreadID( DWORD ID )
	{
		size_t offset = 0;
		bool Save = true;

		for (auto iter = ThreadDataID.begin(); iter != ThreadDataID.end(); iter++, offset++)
		{
			DWORD CurId = *iter;
			if (CurId == ID)
			{
				Save = false;
				break;
			}
		}

		if (Save)
		{
			ThreadDataID.push_back( ID );
		}
		return offset;
	}
}