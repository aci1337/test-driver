#include <Windows.h>
#include <iostream>
#include <random>
#include <dwmapi.h>
#include <winternl.h>
#include "module_spoofing.hpp"
#include <TlHelp32.h>
#define code_rw CTL_CODE(FILE_DEVICE_UNKNOWN, 0x71, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define code_ba CTL_CODE(FILE_DEVICE_UNKNOWN, 0x72, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

#define code_security 0x85b3e12
#define IOCTL_ANTICHEAT 0x222000
#define IOCTL_ROOTKIT 0x222001
#define IOCTL_OBFUSCATE 0x222002
#define IOCTL_ENCRYPT_DATA CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
typedef struct _rw {
	INT32 security;
	INT32 process_id;
	ULONGLONG address;
	ULONGLONG buffer;
	ULONGLONG size;
	BOOLEAN write;
} rw, * prw;

typedef struct _ba {
	INT32 security;
	INT32 process_id;
	ULONGLONG* address;
} ba, * pba;

typedef struct _ga {
	INT32 security;
	ULONGLONG* address;
} ga, * pga;
namespace mem {
	HANDLE driver_handle;
	INT32 process_id;
	HANDLE hEac;
	DWORD dwBytesReturned;

	bool find_driver() {


		driver_handle = CreateFileW((L"\\\\.\\\memebubu"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (!driver_handle || (driver_handle == INVALID_HANDLE_VALUE))
			return false;
		for (int i = 0; i < 2; i++) {
			std::wstring driverName;


			if (i == 0) {
				driverName = L"\\\\.\\battleeye";
				driverName = L"\\\\.\\EasyAntiCheat"; //Line 556  
				//This actually fixxed the whole code:

				//     status = ZwDeviceIoControlFile(hEac, NULL, NULL, NULL, &ioStatus,obfuscateCode, &obfuscateFlag, sizeof(obfuscateFlag) + sizeof(obfuscateBuffer) + antiFingerprint, obfuscateBuffer, outBufLen);
			}
			else {
				driverName = L"\\\\.\\Win32k";
			}
			hEac = CreateFileW(driverName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			//if (hEac == INVALID_HANDLE_VALUE) {
			//    return 0;
			//}
  // Send IOCTL code to driver for anti-cheat
			DWORD antiCheatFlag = 0x0000002;
			DWORD antiCheatBuffer[128];
			DWORD bytesReturned;
			if (!Spoofed_DeviceIoControl(driver_handle, IOCTL_ANTICHEAT, &antiCheatFlag, sizeof(antiCheatFlag), antiCheatBuffer, sizeof(antiCheatBuffer), &bytesReturned, NULL)) {
				std::cout << "Anti-cheat failed\n" << std::endl;
				CloseHandle(driver_handle);
				return 1;
			}
			std::cout << "Anti-Cheat check Succed!\n";
			// Send IOCTL code to driver for rootkit
			DWORD rootkitFlag = 0x0000003;
			DWORD rootkitBuffer[128];
			if (!Spoofed_DeviceIoControl(driver_handle, IOCTL_ROOTKIT, &rootkitFlag, sizeof(rootkitFlag), rootkitBuffer, sizeof(rootkitBuffer), &bytesReturned, NULL)) {
				std::cout << "Rootkit failed\n" << std::endl;
				CloseHandle(driver_handle);
				return 1;
			}
			std::cout << "Rootkit succed!\n";
			// Send IOCTL code to driver to obfuscate code
			DWORD obfuscateCode = 0x80102050;
			DWORD obfuscateFlag = 0x00000004;
			DWORD obfuscateBuffer[128];
			if (!Spoofed_DeviceIoControl(driver_handle, IOCTL_OBFUSCATE, &obfuscateFlag, sizeof(obfuscateFlag), obfuscateBuffer, sizeof(obfuscateBuffer), &bytesReturned, NULL)) {
				std::cout << "Obfuscate failed" << std::endl;
				CloseHandle(driver_handle);
				return 1;
			}
			ULONG antiFingerprint;
			char antiFingerprintBuffer[128];
			SYSTEMTIME systemTime;
			GetSystemTime(&systemTime);
			srand(systemTime.wMilliseconds);
			antiFingerprint = (rand() % 10000) + 1;

			ULONG hiddenFlag = 0x00000001;
			ULONG ctrlCode = 0x80102040;
			IO_STATUS_BLOCK ioStatus;
			ULONG outBufLen = 0;

			if (rand() % 2 == 0)
				ctrlCode += 2;
			else
				ctrlCode -= 4;

			DWORD ba = 0x00000001;
			Spoofed_DeviceIoControl(hEac, 0x80102040, &ba, sizeof(ba), NULL, 0, &dwBytesReturned, NULL);
			CloseHandle(hEac);
			return true;
		}
	}

	void read_physical(PVOID address, PVOID buffer, DWORD size, SIZE_T* bytes_read) {
		_rw arguments = { 0 };

		arguments.security = code_security;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = process_id;
		arguments.write = FALSE;

		*bytes_read = Spoofed_DeviceIoControl(driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	void write_physical(PVOID address, PVOID buffer, DWORD size, SIZE_T* bytes_read) {
		_rw arguments = { 0 };

		arguments.security = code_security;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = process_id;
		arguments.write = TRUE;

		*bytes_read = Spoofed_DeviceIoControl(driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	/*void read_physical(PVOID address, PVOID buffer, DWORD size) {
		_rw arguments = { 0 };

		arguments.security = code_security;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = process_id;
		arguments.write = FALSE;

		Spoofed_DeviceIoControl(driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	void write_physical(PVOID address, PVOID buffer, DWORD size) {
		_rw arguments = { 0 };

		arguments.security = code_security;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = process_id;
		arguments.write = TRUE;

		Spoofed_DeviceIoControl(driver_handle, code_rw, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}*/

	uintptr_t find_image() {
		uintptr_t image_address = { NULL };
		_ba arguments = { NULL };

		arguments.security = code_security;
		arguments.process_id = process_id;
		arguments.address = (ULONGLONG*)&image_address;

		Spoofed_DeviceIoControl(driver_handle, code_ba, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}

	INT32 find_process(LPCTSTR process_name) {
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name)) {
					CloseHandle(hsnap);
					process_id = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);

		return { NULL };
	}
}
/*T read(uint64_t address) {
	T buffer{ };
	SIZE_T bytes_read;
	mem::read_physical((PVOID)address, &buffer, sizeof(T), &bytes_read);
	return buffer;
}

template <typename T>
T write(uint64_t address, T buffer) {
	SIZE_T bytes_read;
	mem::write_physical((PVOID)address, &buffer, sizeof(T), &bytes_read);
	return buffer;
}

i will use the one above soon*/
template <typename T>
T read(uint64_t address) {
	T buffer{ };
	SIZE_T bytes_read;
	mem::read_physical((PVOID)address, &buffer, sizeof(T), &bytes_read);
	return buffer;
}

template <typename T>
T write(uint64_t address, T buffer) {
	SIZE_T bytes_read;
	mem::write_physical((PVOID)address, &buffer, sizeof(T), &bytes_read);
	return buffer;
}
