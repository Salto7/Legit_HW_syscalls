# POC inspired by: https://github.com/WKL-Sec/LayeredSyscall with few changes
* uses 1 VEH
* can strigger HWBP in any way, not necessaruly ACCESS VIOLATION
* no decoy function, leave the call traces as is and break at NT/ZW ntdll function
* at syscall entry, prepare registes and jump to syscall opcode bypassing hooks
* does not use get/set threadcontext or NTContinue to edit the thread contect, instead, modify registers directly (good? ...  bad OPSEC?)
* Works on "solutions" that install hooks on NTDLL only

  
TODO: add more logic to detect hooks, if no hooks exist, execute normally
