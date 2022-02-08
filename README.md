# SnapLoader
#### Using `PssCaptureSnapshot` && `PssWalkSnapshot` to allocate a place to inject your shellcode in `ntdll.dll` memory address space, and taking it step further, hijacking thread without using `GetThreadContext` or `ResumeThread ` or `SuspendThread `

# HOW DOES IT WORK:
* first of all we create our target `RuntimeBroker.exe` process, and get the handles we need to proceed.
* the basic work in this poc was on [GetHiddenInjectionAddress](https://gitlab.com/ORCA666/snaploader/-/blob/main/SnapLoader/Snap.h#L24), which we use `MEMORY_BASIC_INFORMATION / PSS_VA_SPACE_ENTRY` to get the `ntdll.dll` mapped into the target process.
* then when we verify it is `EXECUTE_READ` module && `MEM_IMAGE` (and bigger than 1 MB, which is a stupid way to verify its ntdll.dll lol), but u can use `PSS_VA_SPACE_ENTRY.MappedFileName` to verify it if u want to mess around . 
* later on we search for empty place to write the shellcode [this place must be at least equal to our shellcode size, so very big shellcodes may not work] .
* then i squeeze the base address to the start of ntdll.dll, so since the `stack grow downward` in windows, we use `- ShellcodeSize * 3` [here](https://gitlab.com/ORCA666/snaploader/-/blob/main/SnapLoader/Snap.h#L93) .
* now, moving to running the shellcode, i used the same tech, with `PSS_THREAD_ENTRY` to get the current context of the thread [here](https://gitlab.com/ORCA666/snaploader/-/blob/main/SnapLoader/Snap.h#L177) and then overwriting it with our base address and using `SetThreadContext` to set the context we modified, since our process is suspended, no need to use `ResumeThread` or `SuspendThread` .

# DEMO
<h6 align="center"> <i>idk if it is 100% bypass, rate it </i>  </h6>
![demo](https://gitlab.com/ORCA666/snaploader/-/raw/main/images/Inkedbypassing_peseive_LI.jpg)

# THANKS FOR:
* [psswin32](https://github.com/genghiskMSFT/psswin32)
* [NINA](https://github.com/NtRaiseHardError/NINA)

# AT THE END:
#### This is not a code to bypass Av's as is, but a method used to do so, instead of using `VirtualAllocEx / MapViewOfFile` for example, at the other hand, this poc aims to get rid of typicall and `known` apis.

<h6 align="center"> <i>#                                   STAY TUNED FOR MORE</i>  </h6> 
![120064592-a5c83480-c075-11eb-89c1-78732ecaf8d3](https://gitlab.com/ORCA666/kcthijack/-/raw/main/images/PP.png)
