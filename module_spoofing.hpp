#include <Windows.h>
#include <iostream>
#include <random>
#include <dwmapi.h>
typedef SHORT(*GetAsyncKeyState_t)(int);
typedef INT(*GetSystemMetrics_t)(int);
typedef BOOL(*SetLayeredWindowAttributes_t)(HWND, COLORREF, BYTE, DWORD);
typedef BOOL(*ShowWindow_t)(HWND, int);
typedef HRESULT(*DwmExtendFrameIntoClientArea_t)(HWND, const MARGINS*); //ignore
typedef BOOL(*UpdateWindow_t)(HWND);
typedef HGDIOBJ(*GetStockObject_t)(int);
typedef HANDLE(*CreateThread_t)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
typedef BOOL(*SetWindowPos_t)(HWND, HWND, int, int, int, int, UINT);
typedef LONG(*SetWindowLong_t)(HWND, int, LONG);
typedef HWND(*FindWindow_t)(LPCTSTR, LPCTSTR);
typedef HWND(*CreateWindowA_t)(LPCSTR, LPCTSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);
typedef BOOL(*mouse_event_t)(DWORD, DWORD, DWORD, DWORD, ULONG_PTR);
typedef VOID(*keybd_event_t)(BYTE, BYTE, DWORD, ULONG_PTR);

VOID Spoofed_keybd_event(BYTE bVk, BYTE bScan, DWORD dwFlags, ULONG_PTR dwExtraInfo)
{
	static keybd_event_t origkeybd_event = (keybd_event_t)GetProcAddress(GetModuleHandleA("user32.dll"), "keybd_event");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (bVk == VK_RETURN)
	{
		if (random_number == 0)
			std::cout << "Return key detected!\n";
	}

	return origkeybd_event(bVk, bScan, dwFlags, dwExtraInfo);
}
INT SpoofGetSystemMetrics(int nIndex)
{
	static GetSystemMetrics_t origGetSystemMetrics = (GetSystemMetrics_t)GetProcAddress(GetModuleHandleA("user32.dll"), "GetSystemMetrics");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (nIndex == SM_CXSCREEN)
	{
		if (random_number == 0)
			std::cout << "Screen width detected!\n";
	}

	return origGetSystemMetrics(nIndex);
}

BOOL SpoofSetLayeredWindowAttributes(HWND hwnd, COLORREF crKey, BYTE bAlpha, DWORD dwFlags)
{
	static SetLayeredWindowAttributes_t origSetLayeredWindowAttributes = (SetLayeredWindowAttributes_t)GetProcAddress(GetModuleHandleA("user32.dll"), "SetLayeredWindowAttributes");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (bAlpha == 255)
	{
		if (random_number == 0)
			std::cout << "Window is fully opaque!\n";
	}

	return origSetLayeredWindowAttributes(hwnd, crKey, bAlpha, dwFlags);
}

BOOL SpoofShowWindow(HWND hWnd, int nCmdShow)
{
	static ShowWindow_t origShowWindow = (ShowWindow_t)GetProcAddress(GetModuleHandleA("user32.dll"), "ShowWindow");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (nCmdShow == SW_SHOW)
	{
		if (random_number == 0)
			std::cout << "Window is shown!\n";
	}

	return origShowWindow(hWnd, nCmdShow);
}

HRESULT SpoofDwmExtendFrameIntoClientArea(HWND hWnd, const MARGINS* pMarInset)
{
	static DwmExtendFrameIntoClientArea_t origDwmExtendFrameIntoClientArea = (DwmExtendFrameIntoClientArea_t)GetProcAddress(GetModuleHandleA("user32.dll"), "DwmExtendFrameIntoClientArea");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (pMarInset->cxLeftWidth == 0)
	{
		if (random_number == 0)
			std::cout << "Frame is not extended into client area!\n";
	}

	return origDwmExtendFrameIntoClientArea(hWnd, pMarInset);
}

BOOL SpoofUpdateWindow(HWND hWnd)
{
	static UpdateWindow_t origUpdateWindow = (UpdateWindow_t)GetProcAddress(GetModuleHandleA("user32.dll"), "UpdateWindow");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (IsWindowVisible(hWnd))
	{
		if (random_number == 0)
			std::cout << "Window is visible!\n";
	}

	return origUpdateWindow(hWnd);
}

HGDIOBJ SpoofGetStockObject(int nIndex)
{
	static GetStockObject_t origGetStockObject = (GetStockObject_t)GetProcAddress(GetModuleHandleA("gdi32.dll"), "GetStockObject");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (nIndex == BLACK_BRUSH)
	{
		if (random_number == 0)
			std::cout << "Black brush detected!\n";
	}

	return origGetStockObject(nIndex);
}

HANDLE SpoofCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	static CreateThread_t origCreateThread = (CreateThread_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateThread");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (dwCreationFlags == 0)
	{
		if (random_number == 0)
			std::cout << "Thread is created with default flags!\n";
	}

	return origCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

BOOL SpoofSetWindowPos(HWND hWnd, HWND hWndInsertAfter, int X, int Y, int cx, int cy, UINT uFlags)
{
	static SetWindowPos_t origSetWindowPos = (SetWindowPos_t)GetProcAddress(GetModuleHandleA("user32.dll"), "SetWindowPos");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (uFlags == 0)
	{
		if (random_number == 0)
			std::cout << "Window is set with default flags!\n";
	}

	return origSetWindowPos(hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
}

LONG SpoofSetWindowLong(HWND hWnd, int nIndex, LONG dwNewLong)
{
	static SetWindowLong_t origSetWindowLong = (SetWindowLong_t)GetProcAddress(GetModuleHandleA("user32.dll"), "SetWindowLong");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (nIndex == GWL_STYLE)
	{
		if (random_number == 0)
			std::cout << "Window style is set!\n";
	}

	return origSetWindowLong(hWnd, nIndex, dwNewLong);
}

HWND SpoofFindWindow(LPCTSTR lpClassName, LPCTSTR lpWindowName)
{
	static FindWindow_t origFindWindow = (FindWindow_t)GetProcAddress(GetModuleHandleA("user32.dll"), "FindWindow");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (lpClassName == NULL)
	{
		if (random_number == 0)
			std::cout << "Window is searched by name!\n";
	}

	return origFindWindow(lpClassName, lpWindowName);
}
typedef DWORD(*DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DWORD Spoofed_DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize,
	LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)
{
	static DeviceIoControl_t origDeviceIoControl = (DeviceIoControl_t)GetProcAddress(GetModuleHandleA("kernel32.dll"), "DeviceIoControl");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (dwIoControlCode == 0xA0000)
	{
		if (random_number == 0)
			std::cout << "device IO control code detected!\n";
	}

	return origDeviceIoControl(hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize, lpBytesReturned, lpOverlapped);
}
HWND SpoofCreateWindowA(LPCSTR lpClassName, LPCTSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	static CreateWindowA_t origCreateWindowA = (CreateWindowA_t)GetProcAddress(GetModuleHandleA("user32.dll"), "CreateWindowA");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (dwStyle == WS_VISIBLE)
	{
		if (random_number == 0)
			std::cout << "Window is created with visible style!\n";
	}

	return origCreateWindowA(lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

BOOL Spoofed_mouse_event(DWORD dwFlags, DWORD dx, DWORD dy, DWORD dwData, ULONG_PTR dwExtraInfo)
{
	static mouse_event_t origmouse_event = (mouse_event_t)GetProcAddress(GetModuleHandleA("user32.dll"), "mouse_event");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (dwFlags == MOUSEEVENTF_LEFTDOWN)
	{
		if (random_number == 0)
			std::cout << "button down event detected!\n";
	}

	return origmouse_event(dwFlags, dx, dy, dwData, dwExtraInfo);
}
SHORT Spoofed_GetAsyncKeyState_Spoofed(int vKey)
{
	static GetAsyncKeyState_t origGetAsyncKeyState = (GetAsyncKeyState_t)GetProcAddress(GetModuleHandleA("user32.dll"), "GetAsyncKeyState");

	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, 1);
	int random_number = dis(gen);

	if (vKey == VK_SHIFT)
	{
		if (random_number == 0)
			std::cout << "Shift key detected!\n";
	}

	return origGetAsyncKeyState(vKey);
}