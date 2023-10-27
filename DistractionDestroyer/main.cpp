#define _CRT_SECURE_NO_WARNINGS
#include "wfp.h"
#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include "shobjidl.h"
#include "shlguid.h"
#include "strsafe.h"
#include <fstream>
#pragma comment(lib,"user32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' \
name='Microsoft.Windows.Common-Controls' version='6.0.0.0' \
processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "User32.lib")
#pragma comment(lib, "Msi.lib")
#pragma comment(lib, "Ole32.lib")

using namespace std;
namespace fs = std::filesystem;

LRESULT CALLBACK WindowProcedure(HWND, UINT, WPARAM, LPARAM);
void AddControls(HWND);
HWND EditEnterSite, ListBlockedWebsites, ListAllApps, ListBlockedApps, ButtonEnableDisable, ButtonBlockApp, ButtonUnblockApp, ButtonBlockSite, ButtonUnblockSite;
int sel, sel2, sel3;
wstring stringsel;
vector<wstring> CurrentVector;
wstring AppBeingBlocked;
vector<vector<wstring>> installedAppList;
vector<vector<wstring>> blockList;
vector<wstring> blockedSites;
PacketFilter pktFilter;
const wchar_t* site2;
wstring sitestr;
int count2 = 0;
bool enabled = 0;

bool isValidDomainName(const wchar_t* domainName)
{
	wstring s(domainName);
	for (auto& c : s) c = tolower(c);
	std::wcout << s << endl;
	if (s.compare(0, 4, L"www.") == 0 || s.compare(0, 11, L"http://www.") == 0 || s.compare(0, 12, L"https://www.") == 0)
	{
		s = s.substr(1 + s.find(L"."));
	}
	if ((int)s.find_first_of(L".") < 1)
	{
		return false;
	}
	if ((int)s.find_first_not_of(L"abcdefghijklmnopqrstuvwxyz0123456789-.") > -1)
	{
		return false;
	}
	return true;

}

const wchar_t* processDomainName(const wchar_t* domainName)
{
	wstring s(domainName);
	for (auto& c : s) c = tolower(c);
	if (s.compare(0, 7, L"http://") == 0 || s.compare(0, 8, L"https://") == 0)
	{
		s = s.substr(2 + s.find(L"/"));
	}
	if (s.compare(0, 4, L"www.") == 0)
	{
		s = s.substr(1 + s.find(L"."));
	}
	return s.c_str();
}

vector<vector<wstring>> GetInstalledApps()
{
	vector<vector<wstring>> test;

	CoInitialize(NULL);
	IShellLink* psl;
	CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLink, (LPVOID*)&psl);
	IPersistFile* ppf;
	psl->QueryInterface(IID_IPersistFile, (void**)&ppf);
	cout << "DEBUG2" << endl;

	char* PublicFolder = getenv("PUBLIC");
	string StringPublicFolder = PublicFolder;
	string fullpath1 = StringPublicFolder + "\\Desktop";

	char* UserFolder = getenv("USERPROFILE");
	string StringUserFolder = UserFolder;
	string fullpath2 = StringUserFolder + "\\Desktop";
	string fullpath3 = StringUserFolder + "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs";

	cout << "DEBUG3" << endl;

	string folders[3] = { fullpath1, fullpath2, fullpath3 };

	for (int j = 0; j < 3; j++)
	{
		for (auto const& dir_entry : fs::recursive_directory_iterator(folders[j]))
		{
			wstring extension = dir_entry.path().extension().wstring();
			wstring fullpath = dir_entry.path().wstring();
			wstring directory = dir_entry.path().stem().wstring();
			if (extension == L".lnk")
			{
				wchar_t RawShortcutTarget[MAX_PATH];
				const wchar_t* wsz = fullpath.c_str();
				HRESULT hres1 = ppf->Load(wsz, STGM_READ);
				HRESULT hres2 = psl->GetPath(RawShortcutTarget, MAX_PATH, NULL, SLGP_RAWPATH);
				if (hres2)
				{
					continue;
				}
				wstring ShortcutTarget(RawShortcutTarget);

				if (ShortcutTarget.find(L"System32") != string::npos || ShortcutTarget.find(L"windir") != string::npos) {
					continue;
				}

				vector<wstring> current;
				current.push_back(directory);
				current.push_back(ShortcutTarget);
				test.push_back(current);
			}
		}
	}
	return test;
}

void BlockExecutable(wstring imageFile) {
	wcout << "BlockExecutable imageFile " << imageFile << endl;

	HKEY RegistryKey;

	wstring path1 = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
	wstring fullpath = path1 + imageFile;

	char* WinDir = getenv("windir");
	string StringWinDir = WinDir;
	string fullpath2 = StringWinDir + "\\System32\\wscript.exe ";

	char* AppData = getenv("LOCALAPPDATA");
	string StringAppData = AppData;
	string fullpath3 = StringAppData + "\\DistractionDestroyer\\blocked.vbs";

	string fullpath4 = fullpath2 + fullpath3;

	wstring wfullpath4 = wstring(fullpath4.begin(), fullpath4.end());
	const wchar_t* WideFullPath = wfullpath4.c_str();

	wcout << "Full path " << fullpath.c_str() << "\|\|\|" << endl;
	RegCreateKeyExW(HKEY_LOCAL_MACHINE, fullpath.c_str(), 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &RegistryKey, NULL);
	DWORD GlobalFlagValue = 512;
	RegSetValueExW(RegistryKey, L"Debugger", 0, REG_SZ, (LPBYTE)WideFullPath, 2 * wcslen(WideFullPath));
	RegSetValueExW(RegistryKey, L"GlobalFlag", 0, REG_DWORD, (LPBYTE)&GlobalFlagValue, (DWORD)4);
	return;
}



void UnblockExecutable(wstring imageFile) 
{

	wstring path1 = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\";
	wstring fullpath = path1 + imageFile;

	HKEY RegistryKey;
	wcout << "Full path " << fullpath.c_str() << "\|\|\|" << endl;
	RegCreateKeyExW(HKEY_LOCAL_MACHINE, fullpath.c_str(), 0, NULL, REG_OPTION_VOLATILE, KEY_WRITE, NULL, &RegistryKey, NULL);
	RegDeleteValueW(RegistryKey, L"Debugger");
	return;
}

int enableBlocker()
{
	cout << "Enable blocker: size " << blockList.size() << endl;
	EnableWindow(ButtonUnblockApp, 0);
	EnableWindow(ButtonBlockApp, 0);
	EnableWindow(ButtonUnblockSite, 0);
	EnableWindow(ButtonBlockSite, 0);
	SendMessage(ButtonEnableDisable, WM_SETTEXT, TRUE, (LPARAM)(L"Disable"));

	char* AppData = getenv("LOCALAPPDATA");
	string StringAppData = AppData;
	wofstream BlockedList(StringAppData + "\\DistractionDestroyer\\blocked.dat");

	int lastSlash = 0;
	wstring imageFile;
	for (int i = 0; i < blockList.size(); i += 1)
	{
		lastSlash = blockList[i][1].find_last_of('\\');
		imageFile = blockList[i][1].substr(lastSlash + 1, blockList[i][1].length());
		BlockExecutable(imageFile);
		BlockedList << imageFile.c_str() << endl;
	}
	BlockedList.close();

	WSADATA hrt;
	WSAStartup(MAKEWORD(2, 2), &hrt);
	for (int i = 0; i < blockedSites.size(); i += 1)
	{
		string ANSIblockedSite(blockedSites[i].begin(), blockedSites[i].end());
		pktFilter.BlockDomain(ANSIblockedSite.c_str());
	}
	pktFilter.StartFirewall();
	return 0;
}

int disableBlocker()
{
	cout << "Disable blocker: size " << blockList.size() << endl;
	pktFilter.StopFirewall();
	PacketFilter pktFilter;
	EnableWindow(ButtonUnblockApp, 1);
	EnableWindow(ButtonBlockApp, 1);
	EnableWindow(ButtonUnblockSite, 1);
	EnableWindow(ButtonBlockSite, 1);
	SendMessage(ButtonEnableDisable, WM_SETTEXT, TRUE, (LPARAM)(L"Enable"));

	int lastSlash = 0;
	wstring imageFile;
	for (int i = 0; i < blockList.size(); i += 1)
	{
		lastSlash = blockList[i][1].find_last_of('\\');
		imageFile = blockList[i][1].substr(lastSlash + 1, blockList[i][1].length());
		wcout << "Unblock image file: " << imageFile << endl;
		UnblockExecutable(imageFile);
	}
	char* AppData = getenv("LOCALAPPDATA");
	string StringAppData = AppData;
	StringAppData += "\\DistractionDestroyer\\blocked.dat";
	DeleteFileA(StringAppData.c_str());
	return 0;
}

int WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR args, int ncmdshow)
{
	char* AppData = getenv("LOCALAPPDATA");
	string StringAppData = AppData;

	if (!filesystem::exists(StringAppData + "\\DistractionDestroyer\\blocked.vbs"))
	{
		fs::create_directory(StringAppData + "\\DistractionDestroyer");
		ofstream BlockedScript(StringAppData + "\\DistractionDestroyer\\blocked.vbs");
		BlockedScript << "Response = MsgBox(\"This program has been blocked by Distraction Destroyer\", vbOKOnly Or vbCritical, \"Distraction Destroyer\")";
		BlockedScript.close();
	}

	WNDCLASSW wc = { 0 };
	wc.hbrBackground = (HBRUSH)COLOR_WINDOW;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hInstance = hInst;
	wc.lpszClassName = L"DistractionDestroyer";
	wc.lpfnWndProc = WindowProcedure;

	if (!RegisterClassW(&wc)) {
		return -1;
	}

	CreateWindowW(L"DistractionDestroyer", L"Distraction Destroyer", WS_OVERLAPPED | WS_MINIMIZEBOX | WS_SYSMENU | WS_VISIBLE, 100, 100, 640, 384, NULL, NULL, NULL, NULL);

	MSG msg = { 0 };

	while (GetMessage(&msg, NULL, NULL, NULL))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}

LRESULT CALLBACK WindowProcedure(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp)
{
	switch (msg)
	{
	case WM_CREATE:
		AddControls(hWnd);
		break;
	case WM_DESTROY:
		disableBlocker();
		PostQuitMessage(0);
		break;
	case WM_COMMAND:
		switch (wp)
		{
		case 1:
			sel2 = SendMessageW(ListAllApps, LB_GETCURSEL, 0, 0);
			if (sel2 == -1)
			{
				break;
			}
			wchar_t seltext2[100];
			SendMessageW(ListAllApps, LB_GETTEXT, (WPARAM)sel2, (LPARAM)&seltext2);
			stringsel = seltext2;
			SendMessageW(ListAllApps, LB_DELETESTRING, (WPARAM)sel2, 0);
			SendMessageW(ListBlockedApps, LB_ADDSTRING, 0, (LPARAM)seltext2);
			AppBeingBlocked = installedAppList[sel2][1];
			installedAppList.erase(installedAppList.begin() + sel2);
			wcout << AppBeingBlocked << endl;
			CurrentVector.clear();
			CurrentVector.push_back(stringsel);
			CurrentVector.push_back(AppBeingBlocked);
			blockList.push_back(CurrentVector);
			break;
		case 2:
			sel3 = SendMessageW(ListBlockedApps, LB_GETCURSEL, 0, 0);
			if (sel3 == -1)
			{
				break;
			}
			wchar_t seltext3[100];
			SendMessageW(ListBlockedApps, LB_GETTEXT, (WPARAM)sel3, (LPARAM)&seltext3);
			stringsel = seltext3;
			SendMessageW(ListBlockedApps, LB_DELETESTRING, (WPARAM)sel3, 0);
			SendMessageW(ListAllApps, LB_ADDSTRING, 0, (LPARAM)seltext3);
			AppBeingBlocked = blockList[sel3][1];
			blockList.erase(blockList.begin() + sel3);
			CurrentVector.clear();
			CurrentVector.push_back(stringsel);
			CurrentVector.push_back(AppBeingBlocked);
			installedAppList.push_back(CurrentVector);
			break;
		case 4:
			wchar_t site[100];
			GetWindowText(EditEnterSite, site, 100);
			if (!isValidDomainName(site))
			{
				MessageBoxW(hWnd, L"Invalid domain name", L"Error", MB_ICONERROR | MB_OK);
				break;
			}
			SetWindowText(EditEnterSite, 0);
			site2 = processDomainName(site);
			blockedSites.push_back(site2);

			count2 = 0;
			sitestr = site2;

			for (int i = 0; i < sitestr.size(); i++)
			{
				if (sitestr[i] == '.')
				{
					count2++;
				}
			}
			if (count2 == 1)
			{
				sitestr = L"www." + sitestr;
				blockedSites.push_back(sitestr.c_str());
			}

			SendMessageW(ListBlockedWebsites, LB_ADDSTRING, 0, (LPARAM)site);
			break;
		case 5:
			sel = SendMessageW(ListBlockedWebsites, LB_GETCURSEL, 0, 0);
			if (sel == -1)
			{
				break;
			}
			wchar_t seltext[100];
			blockedSites.erase(blockedSites.begin() + sel);
			SendMessageW(ListBlockedWebsites, LB_GETTEXT, (WPARAM)sel, (LPARAM)&seltext);
			SendMessageW(ListBlockedWebsites, LB_DELETESTRING, (WPARAM)sel, 0);
			cout << sel << endl;
			break;
		case 6:
			if (enabled)
			{
				disableBlocker();
				enabled = 0;
			}
			else
			{
				enableBlocker();
				enabled = 1;
			}
		}
		break;
	default:
		return DefWindowProcW(hWnd, msg, wp, lp);
	}
}

void AddControls(HWND hWnd)
{
	HFONT ListBoxFont = CreateFontW(20, 0, 0, 0, FW_MEDIUM, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
	HFONT ButtonFont = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Arial");
	HFONT EnableDisableFont = CreateFontW(40, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, ANSI_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Arial");

	HWND TextBlockedWebsites = CreateWindowW(L"Static", L"Blocked websites:", WS_VISIBLE | WS_CHILD, 25, 25, 200, 50, hWnd, NULL, NULL, NULL);
	HWND TextAllApps = CreateWindowW(L"Static", L"Apps:", WS_VISIBLE | WS_CHILD, 220, 25, 50, 50, hWnd, NULL, NULL, NULL);
	HWND TextBlockedApps = CreateWindowW(L"Static", L"Blocked apps:", WS_VISIBLE | WS_CHILD, 415, 25, 100, 50, hWnd, NULL, NULL, NULL);

	ListBlockedWebsites = CreateWindowW(L"ListBox", NULL, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL | WS_HSCROLL, 25, 50, 170, 120, hWnd, (HMENU)3, NULL, NULL);
	ListAllApps = CreateWindowW(L"ListBox", NULL, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL | WS_HSCROLL, 220, 50, 170, 120, hWnd, (HMENU)6, NULL, NULL);
	ListBlockedApps = CreateWindowW(L"ListBox", NULL, WS_CHILD | WS_VISIBLE | LBS_NOTIFY | WS_VSCROLL | WS_HSCROLL, 415, 50, 170, 120, hWnd, (HMENU)7, NULL, NULL);

	ButtonBlockSite = CreateWindowW(L"Button", L"Block site", WS_VISIBLE | WS_CHILD, 25, 230, 80, 25, hWnd, (HMENU)4, NULL, NULL);
	ButtonUnblockSite = CreateWindowW(L"Button", L"Unblock selected site", WS_VISIBLE | WS_CHILD, 25, 170, 150, 25, hWnd, (HMENU)5, NULL, NULL);
	ButtonBlockApp = CreateWindowW(L"Button", L"Block selected app", WS_VISIBLE | WS_CHILD, 325, 170, 140, 25, hWnd, (HMENU)1, NULL, NULL);
	ButtonUnblockApp = CreateWindowW(L"Button", L"Unblock selected app", WS_VISIBLE | WS_CHILD, 315, 200, 160, 25, hWnd, (HMENU)2, NULL, NULL);
	ButtonEnableDisable = CreateWindowW(L"Button", L"Enable", WS_VISIBLE | WS_CHILD, 295, 240, 200, 70, hWnd, (HMENU)6, NULL, NULL);

	EditEnterSite = CreateWindowW(L"Edit", L"", WS_VISIBLE | WS_CHILD, 25, 200, 200, 25, hWnd, NULL, NULL, NULL);

	SendMessage(ButtonBlockSite, WM_SETFONT, WPARAM(ButtonFont), TRUE);
	SendMessage(ButtonUnblockSite, WM_SETFONT, WPARAM(ButtonFont), TRUE);
	SendMessage(ButtonUnblockApp, WM_SETFONT, WPARAM(ButtonFont), TRUE);
	SendMessage(ButtonBlockApp, WM_SETFONT, WPARAM(ButtonFont), TRUE);
	SendMessage(ButtonEnableDisable, WM_SETFONT, WPARAM(EnableDisableFont), TRUE);

	SendMessage(TextBlockedWebsites, WM_SETFONT, WPARAM(ListBoxFont), TRUE);
	SendMessage(TextAllApps, WM_SETFONT, WPARAM(ListBoxFont), TRUE);
	SendMessage(TextBlockedApps, WM_SETFONT, WPARAM(ListBoxFont), TRUE);

	SendMessage(ListBlockedWebsites, WM_SETFONT, WPARAM(ButtonFont), TRUE);
	SendMessage(ListAllApps, WM_SETFONT, WPARAM(ButtonFont), TRUE);
	SendMessage(ListBlockedApps, WM_SETFONT, WPARAM(ButtonFont), TRUE);

	SendMessage(EditEnterSite, WM_SETFONT, WPARAM(ButtonFont), TRUE);

	installedAppList = GetInstalledApps();

	std::sort(installedAppList.begin(), installedAppList.end(),
		[](const std::vector<wstring>& a, const std::vector<wstring>& b) {
			return a[0] < b[0];
		});

	for (int i = 0; i < installedAppList.size(); i += 1)
	{
		//wcout << i << " = " << installedAppList[i][0] << endl;
		wchar_t currentApp[255]{};
		installedAppList[i][0].copy(currentApp, 255);
		SendMessageW(ListAllApps, LB_ADDSTRING, 0, (LPARAM)currentApp);
	}

	char* AppData = getenv("LOCALAPPDATA");
	string StringAppData = AppData;
	if (filesystem::exists(StringAppData + "\\DistractionDestroyer\\blocked.dat"))
	{
		char* AppData = getenv("LOCALAPPDATA");
		string StringAppData = AppData;
		wifstream BlockedList(StringAppData + "\\DistractionDestroyer\\blocked.dat");
		for (std::wstring line; getline(BlockedList, line); )
		{
			UnblockExecutable(line);
		}
		DeleteFileA(StringAppData.c_str());
	}
}