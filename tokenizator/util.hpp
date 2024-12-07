#pragma once

#include <iostream>
#include <string>
#include <windows.h>
#include <winhttp.h>
#include <Wbemidl.h>
#include <comutil.h>
#include <tlhelp32.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comsuppw.lib")

static bool EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp{};
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

static DWORD findProcessByServiceName(const std::wstring& serviceName) {
    IWbemLocator* pLoc = nullptr;
    IWbemServices* pSvc = nullptr;
    HRESULT hres;

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library.\n";
        return 0;
    }

    hres = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE, nullptr);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM security.\n";
        CoUninitialize();
        return 0;
    }

    hres = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object.\n";
        CoUninitialize();
        return 0;
    }

    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        std::cerr << "Failed to connect to WMI namespace.\n";
        pLoc->Release();
        CoUninitialize();
        return 0;
    }

    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hres)) {
        std::cerr << "Failed to set proxy blanket.\n";
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 0;
    }

    IEnumWbemClassObject* pEnumerator = nullptr;
    std::wstring query = L"SELECT ProcessId FROM Win32_Service WHERE Name = '" + serviceName + L"'";
    hres = pSvc->ExecQuery(bstr_t(L"WQL"), bstr_t(query.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, nullptr, &pEnumerator);

    if (FAILED(hres)) {
        std::cerr << "Query for service failed.\n";
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 0;
    }

    IWbemClassObject* pClsObj = nullptr;
    ULONG uReturn = 0;
    DWORD processID = 0;

    if (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pClsObj, &uReturn);
        if (0 == uReturn) {
            std::cerr << "No service found with the specified name.\n";
        }
        else {
            VARIANT vtProp;
            VariantInit(&vtProp);
            hr = pClsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
            if (SUCCEEDED(hr)) {
                processID = vtProp.uintVal;
                VariantClear(&vtProp);
            }
            pClsObj->Release();
        }
        pEnumerator->Release();
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return processID;
}

DWORD GetProcessIdByName(const wchar_t* processName) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    DWORD processID = 0;
    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                processID = pe32.th32ProcessID;
                break;
            }
        } while (Process32NextW(hSnap, &pe32));
    }

    CloseHandle(hSnap);
    return processID;
}