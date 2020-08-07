# ColdHide

ColdHide is a mini and simple open source user mode anti-anti debug library x86/x64 for Windows.
To inject this library try using [ColdMDLoader](https://github.com/Rat431/ColdMDLoader).

## Hooks
 - ***PEB hooking***
 - ***NtQueryInformationProcess***
 - ***NtClose***
 - ***Drx hooking***
 - ***NtQueryObject***
 - ***NtQuerySystemInformation***
 - ***NtSetInformationThread***
 - ***NtSetInformationProcess***
 - ***NtCreateThreadEx***
 - ***NtYieldExecution***
 - ***NtSetDebugFilterState***
 - ***Process32FirstW***
 - ***Process32NextW***
 - ***GetTickCount***
 - ***GetTickCount64***
 - ***Anti-Anti attach***
  

## Build requirements
- MSVC 2019 or higher build tools are required to compile this project.

## Credits
- [Zydis (Disassembler engine)](https://github.com/zyantific/zydis)
- [ColdHook (Hooking library)](https://github.com/Rat431/ColdHook)
