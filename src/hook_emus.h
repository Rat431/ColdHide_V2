/*
	Copyright (c) 2020 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#pragma once
#include "Defs.h"
#include <tlhelp32.h>

// Define original functions
typedef NTSTATUS( NTAPI * __NtQueryInformationProcess__ )(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS( NTAPI * __NtSetInformationThread__ )(HANDLE, THREADINFOCLASS, PVOID, ULONG);
typedef NTSTATUS( NTAPI * __NtQuerySystemInformation__ )(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS( NTAPI * __NtClose__ )(HANDLE);
typedef NTSTATUS( NTAPI * __NtQueryObject__ )(HANDLE, OBJECT_INFORMATION_CLASS, PVOID, ULONG, PULONG);
typedef NTSTATUS( NTAPI * __NtGetContextThread__ )(HANDLE, PCONTEXT);
typedef NTSTATUS( NTAPI * __NtSetContextThread__ )(HANDLE, PCONTEXT);
typedef NTSTATUS( NTAPI * __NtContinue__ )(PCONTEXT, BOOLEAN);
typedef NTSTATUS( NTAPI * __NtCreateThreadEx__ )(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);
typedef NTSTATUS( NTAPI * __NtSetInformationProcess__ )(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);
typedef NTSTATUS( NTAPI * __NtYieldExecution__ )();
typedef NTSTATUS( NTAPI * __NtSetDebugFilterState__ )(ULONG, ULONG, BOOLEAN);

typedef VOID( NTAPI * __KiUserExceptionDispatcher__ )(PEXCEPTION_RECORD, PCONTEXT);
typedef BOOL( WINAPI * __Process32First__ )(HANDLE, LPPROCESSENTRY32);
typedef BOOL( WINAPI * __Process32Next__ )(HANDLE, LPPROCESSENTRY32);

namespace Hook_emu
{
	void InitHookFunctionsVars();

	// proxied functions 
	NTSTATUS NTAPI __NtQueryInformationProcess( HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG  ProcessInformationLength, PULONG ReturnLength );
	NTSTATUS NTAPI __NtSetInformationThread( HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength );
	NTSTATUS NTAPI __NtQuerySystemInformation( SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength );
	NTSTATUS NTAPI __NtClose( HANDLE Handle );
	NTSTATUS NTAPI __NtQueryObject( HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass, PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength );

	// DRx functions
	NTSTATUS NTAPI __NtGetContextThread( HANDLE ThreadHandle, PCONTEXT pContext );
	NTSTATUS NTAPI __NtSetContextThread( HANDLE ThreadHandle, PCONTEXT pContext );

	NTSTATUS NTAPI __NtContinue( PCONTEXT ThreadContext, BOOLEAN RaiseAlert );
	NTSTATUS NTAPI __NtCreateThreadEx( PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList );
	NTSTATUS NTAPI __NtSetInformationProcess( HANDLE ProcessHandle, PROCESS_INFORMATION_CLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength );
	NTSTATUS NTAPI __NtYieldExecution();
	NTSTATUS NTAPI __NtSetDebugFilterState( ULONG ComponentId, ULONG Level, BOOLEAN State );

	VOID NTAPI __KiUserExceptionDispatcher( PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context );
	VOID NTAPI __RKiUserExceptionDispatcher( PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context );


	BOOL WINAPI __Process32FirstW( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
	BOOL WINAPI __Process32NextW( HANDLE hSnapshot, LPPROCESSENTRY32 lppe );
	DWORD WINAPI __GetTickCount();
	ULONGLONG WINAPI __GetTickCount64();
}