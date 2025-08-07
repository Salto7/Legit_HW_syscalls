# POC for indirect syscalls using HWBP with "kinda" legit stacks
* inspired by  https://github.com/WKL-Sec/LayeredSyscall with some changes
* uses 1 VEH, ie less HWBP noise and hopefully less IOC in stack frames
* can strigger HWBP in any way, not necessaruly ACCESS VIOLATION
* no decoy function,  prepare the exception handler and call the kernelbase/kernel32 function, then break and the NTDLL function before the syscall. This help keeping legit call traces
* at NTDLL function entry, prepare registes and jump to syscall opcode bypassing hooks (this version of the code does not check if hooks exist, but this is veryeasyto implement)
* does not use getter/setter for threadcontext or NTContinue to edit the thread context, instead, modify registers directly (good? ...  bad OPSEC?)
* Works on "solutions" that install hooks on NTDLL only

One caveat is, a wrapper function is needed for each winapi call, its easy though, check the example wrappers in FuncWrappers.cpp and FuncWrappers.h

TODO: add more logic to detect hooks, if no hooks exist, execute normally
