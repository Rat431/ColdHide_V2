/*
	Copyright (c) 2020 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#pragma once
#include "hook_emus.h"
#include "ColdHook/ColdHook.h"

namespace Hooks_Informastion
{
	extern DWORD CurrentProcessID;
	extern ULONG_PTR FPPID;

	// PEB.
	extern void * PEB_BeingDebuggedP;
	extern int32_t PEB_BeingDebuggedID;

	extern void * PEB_NtGlobalFlagP;
	extern int32_t PEB_NtGlobalFlagID;

	// HeapFlags
	extern void * FlagsHeapFlagsP;
	extern int32_t FlagsHeapFlagsID;

	// Some ntdll apis
	extern void * Nt_QueryProcessP;
	extern int32_t Nt_QueryProcessID;

	extern void * Nt_QuerySystemP;
	extern int32_t Nt_QuerySystemID;

	extern void * Nt_SetThreadInformationP;
	extern int32_t Nt_SetThreadInformationID;

	extern void * Nt_CloseP;
	extern int32_t Nt_CloseID;

	extern void * Nt_QueryObjectP;
	extern int32_t Nt_QueryObjectID;

	extern void * Nt_NtGetContextThreadP;
	extern int32_t Nt_NtGetContextThreadID;

	extern void * Nt_NtSetContextThreadP;
	extern int32_t Nt_NtSetContextThreadID;

	extern void * Nt_ContinueP;
	extern int32_t Nt_ContinueID;

	extern void * Nt_CreateThreadExP;
	extern int32_t Nt_CreateThreadExID;

	extern void * Nt_ExceptionDispatcherP;
	extern int32_t Nt_ExceptionDispatcherID;

	extern void * Nt_SetInformationProcessP;
	extern int32_t Nt_SetInformationProcessID;

	extern void * Nt_YieldExecutionP;
	extern int32_t Nt_YieldExecutionID;

	extern void * Nt_SetDebugFilterStateP;
	extern int32_t Nt_SetDebugFilterStateID;

	extern void * Kernel32_Process32FirstWP;
	extern int32_t Kernel32_Process32FirstWID;

	extern void * Kernel32_Process32NextWP;
	extern int32_t Kernel32_Process32NextWID;

	extern void * Kernel32_GetTickCountP;
	extern int32_t Kernel32_GetTickCountID;

	extern void * Kernel32_GetTickCount64P;
	extern int32_t Kernel32_GetTickCount64ID;
}
namespace Hooks_Config
{
	// Hide PEB.
	extern bool HideWholePEB;
	extern bool PEB_BeingDebugged;
	extern bool PEB_NtGlobalFlag;

	// HeapFlags
	extern bool HeapFlags;

	// DRx
	extern bool HideWholeDRx;
	extern bool FakeContextEmulation;

	extern bool DRx_ThreadContextRead;
	extern bool DRx_ThreadContextWrite;
	extern bool Nt_Continue;
	extern bool Nt_KiUserExceptionDispatcher;

	// Anti attach
	extern bool Anti_Anti_Attach;

	// Some ntdll apis
	extern bool Nt_QueryProcess;
	extern bool Nt_QuerySystem;
	extern bool Nt_SetThreadInformation;
	extern bool Nt_Close;
	extern bool Nt_QueryObject;
	extern bool Nt_CreateThreadEx;
	extern bool Nt_SetInformationProcess;
	extern bool Nt_YieldExecution;
	extern bool Nt_SetDebugFilterState;

	extern bool Kernel32_Process32First;
	extern bool Kernel32_Process32Next;
	extern bool Kernel32_GetTickCount;
	extern bool Kernel32_GetTickCount64;
}
namespace Hooks
{
	static void HidePEB();
	static void HideDRx();
	static void HideProcessInformations();
	static void HideSetInformationThread();
	static void HideQuerySystemInformation();
	static void HideCloseHandle();
	static void HideQueryObject();
	static void HideSetInformationProcess();
	static void HideNtContinue();
	static void HideCreateThreadEx();
	static void HideExceptionDispatcher();
	static void HideYieldExecution();
	static void HideSetDebugFilterState();
	static void HideAntiAntiAttach();

	static void HideProcess32First();
	static void HideProcess32Next();
	static void HideGetTickCount();
	static void HideGetTickCount64();
}
namespace Hooks_Manager
{
	// Init and ShutDown
	void Init( HMODULE hMain );
	void ShutDown();

	// Configuration
	static void ReadIni();
	static void InitInternalPath( HMODULE hMain );

	void GetExplorerPID();
	size_t GetOffsetByThreadID( DWORD ID );
}