/*
	Copyright (c) 2020 Rat431 (https://github.com/Rat431).
	This software is under the MIT license, for more informations check the LICENSE file.
*/

#include "hooks.h"

// small export
extern "C" _declspec(dllexport) void CHide_Bridge() { return; }

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		Hooks_Manager::Init(hModule);
	}
	else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
		Hooks_Manager::ShutDown();
	}
	return TRUE;
}

