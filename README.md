# APICallProxy

This Project is for Windows API Call Obfuscation to make static/Dynamic analysis of a program harder, and to make it harder to recognize and extract the sequance of Windows API the application Call.

It Work by replacing normal calls to windows API like **CreateFile**, **WriteFile**, **OpenProcess**,.. with a **DeviceIoControl** with the appropriate **IOCTL** code

 
# Windows API:

- [x] **CreateFile**
- [x] **OpenFile**
- [x] **DeleteFile**
- [x] **WriteFile**
- [x] **ReadFile**
- [x] **OpenProcess**
- [x] **TerminateProcess**
- [x] **OpenThread**
- [x] **CloseHandle**
- [x] **GetFileSize**
- [x] **ZwQuerySystemInformation**
- [x] **ZwAllocateVirtualMemory**
- [x] **VirtualProtectEx**
- [x] **WriteProcessMemory**
- [x] **ReadProcessMemory**
- [x] **NtSuspendProcess**
- [x] **NtResumeProcess**
- [x] **ZwCreateSection**
- [x] **ZwOpenSection**
- [x] **ZwMapViewOfSection**
- [x] **ZwUnmapViewOfSection**
- [x] **SetThreadContext**
- [x] **GetThreadContext**
- [ ] **CreateThread**
- [ ] **CreateRemoteThread**
- [ ] **ResumeThread**
- [ ] **SuspendThread**
- [ ] **RegCreateKeyW**
- [ ] **RegDeleteKeyW**
- [ ] **RegGetValueW**
- [ ] **RegEnumValueW**
- [ ] **RegQueryValueW**
- [ ] **RegRenameKey**
- [ ] **RegSetValueW**
- [ ] **NtLoadDriver**
- [ ] **NtUnloadDriver**


- [x] **Get_ProcessID_From_Process_Name**         not windows API but usefull utility (can use ZwQuerySystemInformation to do the same)

```
I Create a sample Client that will do APC injection as demo, and i will try to add more demo soon

Note that the APCInjector.exe only work as x64 bit application on x64 bit windows because the shellcode is x64 bit

i tested the Driver and the client communication on windows 10 0x64 and window 8.1 x64/x86 bit

Kindly let me know if you faced any crash, need some clarefication, or have any comment for improvement you can reach out to me on my twitter @7odaZohdy or by mail abdelaziz.zohdy@gmail.com 
```