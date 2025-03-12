#include "pch.h" // Include precompiled header
#include "TrafficMonitor.h"
#include <TlHelp32.h>
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 26819)
#pragma warning(disable: 26495)
#include <nlohmann/json.hpp>
#pragma warning(pop)
#endif
#include <psapi.h> // Required for QueryFullProcessImageName
#include <iphlpapi.h>

extern std::string appPath = ""; // Correct path to the executable

extern std::string workingDir = GetWorkingDirectory(appPath); // Correct working directory for the application
std::atomic<bool> keepMonitoringApplication;

std::string WideStringToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();

    int sizeNeeded = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(sizeNeeded, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), (int)wstr.size(), &strTo[0], sizeNeeded, NULL, NULL);
    return strTo;
}

std::vector<DWORD> GetAllPidsByAppName(const std::string& appName) {
    std::vector<DWORD> pids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create process snapshot. Error code: " << GetLastError() << std::endl;
        return pids;
    }

    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    if (Process32First(snapshot, &entry)) {
        do {
            std::string processName = WideStringToUtf8(entry.szExeFile);
            if (processName == appName) {
                pids.push_back(entry.th32ProcessID);
            }
        } while (Process32Next(snapshot, &entry));
    }
    else {
        std::cerr << "Process enumeration failed. Error code: " << GetLastError() << std::endl;
    }

    CloseHandle(snapshot);
    return pids;
}

std::string ConstructPidFilter(const std::vector<DWORD>& pids) {
    std::string filter;
    for (size_t i = 0; i < pids.size(); ++i) {
        filter += "processId = " + std::to_string(pids[i]);
        if (i < pids.size() - 1) {
            filter += " or ";
        }
    }
    return filter;
}

// Helper function to retrieve the application name from a PID
std::string GetApplicationNameFromPid(DWORD pid) {
    if (pid == 0) {
        return "Unknown"; // PID 0 does not correspond to a specific process
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return "Unknown"; // Could not open process
    }

    char processName[MAX_PATH] = "<unknown>";
    DWORD processNameSize = MAX_PATH; // Declare a DWORD to store the size

    if (QueryFullProcessImageNameA(hProcess, 0, processName, &processNameSize)) {
        // Extract only the file name from the full path
        std::string fullPath = processName;
        size_t lastSlash = fullPath.find_last_of("\\/");
        CloseHandle(hProcess);
        return lastSlash != std::string::npos ? fullPath.substr(lastSlash + 1) : fullPath;
    }

    CloseHandle(hProcess);
    return "Unknown";
}

std::string ConvertIPv4ToString(ULONG ipAddress) {
    std::ostringstream oss;
    oss << ((ipAddress & 0xFF)) << "."
        << ((ipAddress >> 8) & 0xFF) << "."
        << ((ipAddress >> 16) & 0xFF) << "."
        << ((ipAddress >> 24) & 0xFF);
    return oss.str();
}

DWORD GetProcessIdFromPacket(const WINDIVERT_ADDRESS& addr, char* packet, UINT packetLen) {
    // Parse the packet to get the IP headers
    WINDIVERT_IPHDR* ip_header = (WINDIVERT_IPHDR*)packet;

    // Validate packet length
    if (packetLen < sizeof(WINDIVERT_IPHDR)) {
        return 0; // Invalid packet length for IP header
    }

    ULONG srcAddr = ip_header->SrcAddr;
    USHORT srcPort = 0;

    // Determine whether it's TCP or UDP
    if (ip_header->Protocol == IPPROTO_TCP) {
        WINDIVERT_TCPHDR* tcp_header = (WINDIVERT_TCPHDR*)(packet + (ip_header->HdrLength * 4));
        srcPort = ntohs(tcp_header->SrcPort);

        // Check the TCP table for matching connections
        ULONG ulSize = sizeof(MIB_TCPTABLE_OWNER_PID); // Minimum size initially
        PMIB_TCPTABLE_OWNER_PID pTCPInfo = (PMIB_TCPTABLE_OWNER_PID)malloc(ulSize);

        if (!pTCPInfo) {
            std::cerr << "Memory allocation failed for TCP table." << std::endl;
            return 0;
        }

        DWORD dwResult = GetExtendedTcpTable(pTCPInfo, &ulSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
        if (dwResult == ERROR_INSUFFICIENT_BUFFER) {
            free(pTCPInfo);
            pTCPInfo = (PMIB_TCPTABLE_OWNER_PID)malloc(ulSize); // Reallocate with correct size

            if (pTCPInfo && GetExtendedTcpTable(pTCPInfo, &ulSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pTCPInfo->dwNumEntries; i++) {
                    if (pTCPInfo->table[i].dwLocalAddr == srcAddr && ntohs((u_short)pTCPInfo->table[i].dwLocalPort) == srcPort) {
                        DWORD pid = pTCPInfo->table[i].dwOwningPid;
                        free(pTCPInfo);
                        return pid;
                    }
                }
            }
        }
        free(pTCPInfo);
    }
    else if (ip_header->Protocol == IPPROTO_UDP) {
        WINDIVERT_UDPHDR* udp_header = (WINDIVERT_UDPHDR*)(packet + (ip_header->HdrLength * 4));
        srcPort = ntohs(udp_header->SrcPort);

        // Check the UDP table for matching connections
        ULONG ulSize = sizeof(MIB_UDPTABLE_OWNER_PID); // Minimum size initially
        PMIB_UDPTABLE_OWNER_PID pUDPInfo = (PMIB_UDPTABLE_OWNER_PID)malloc(ulSize);

        if (!pUDPInfo) {
            std::cerr << "Memory allocation failed for UDP table." << std::endl;
            return 0;
        }

        DWORD dwResult = GetExtendedUdpTable(pUDPInfo, &ulSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
        if (dwResult == ERROR_INSUFFICIENT_BUFFER) {
            free(pUDPInfo);
            pUDPInfo = (PMIB_UDPTABLE_OWNER_PID)malloc(ulSize); // Reallocate with correct size

            if (pUDPInfo && GetExtendedUdpTable(pUDPInfo, &ulSize, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0) == NO_ERROR) {
                for (DWORD i = 0; i < pUDPInfo->dwNumEntries; i++) {
                    if (pUDPInfo->table[i].dwLocalAddr == srcAddr && ntohs((u_short)pUDPInfo->table[i].dwLocalPort) == srcPort) {
                        DWORD pid = pUDPInfo->table[i].dwOwningPid;
                        free(pUDPInfo);
                        return pid;
                    }
                }
            }
        }
        free(pUDPInfo);
    }

    // If no match found, return 0
    return 0;
}

DWORD GetProcessIdFromPacket(const IPV4_HEADER* ipHeader) {
    DWORD pid = 0;
    ULONG ulSize = sizeof(MIB_TCPTABLE_OWNER_PID); // Initialize with the size of one TCP table structure
    PMIB_TCPTABLE_OWNER_PID tcpTable = nullptr;

    // Extract the transport protocol and ports
    uint8_t protocol = ipHeader->protocol; // Extract protocol from IPv4 header
    uint16_t srcPort = 0, destPort = 0;

    // Calculate the offset to the transport-layer header
    unsigned int ipHeaderLength = (ipHeader->version_ihl & 0x0F) * 4; // Header length in bytes
    const uint8_t* transportHeader = (const uint8_t*)ipHeader + ipHeaderLength;

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
        // Extract source and destination ports
        srcPort = ntohs(*(uint16_t*)transportHeader);           // Source port
        destPort = ntohs(*(uint16_t*)(transportHeader + 2));    // Destination port
    }
    else {
        return 0; // Not TCP/UDP, unable to associate packet with a PID
    }

    // Step 1: Call GetExtendedTcpTable to determine the required size
    DWORD result = GetExtendedTcpTable(nullptr, &ulSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result != ERROR_INSUFFICIENT_BUFFER) {
        std::cerr << "Failed to retrieve buffer size. Error: " << result << std::endl;
        return 0; // Exit gracefully if the size cannot be determined
    }

    // Step 2: Allocate memory for the TCP table
    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(ulSize);
    if (tcpTable == nullptr) {
        std::cerr << "Memory allocation failed for TCP table." << std::endl;
        return 0; // Exit if memory allocation fails
    }

    // Step 3: Retrieve the actual TCP table
    result = GetExtendedTcpTable(tcpTable, &ulSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (result == NO_ERROR) {
        // Match the packet's source/destination with the TCP table entries
        for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
            auto entry = tcpTable->table[i];
            if (entry.dwLocalAddr == ipHeader->src_addr &&
                ntohs((u_short)entry.dwLocalPort) == srcPort) {
                pid = entry.dwOwningPid;
                break; // Match found
            }
        }
    }
    else {
        std::cerr << "Failed to retrieve TCP table. Error: " << result << std::endl;
    }

    // Step 4: Free allocated memory
    free(tcpTable);
    tcpTable = nullptr;

    return pid; // Return the process ID (or 0 if not found)
}

void LaunchPowerShellScript(const std::string& scriptPath) {
    std::wstring command = L"powershell.exe -File " + ConvertToWideString(scriptPath);
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 };

    if (!CreateProcess(NULL, &command[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "Failed to launch PowerShell script. Error code: " << GetLastError() << std::endl;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

DWORD GetProcessIdByName(const std::wstring& processName) {
    DWORD processId = 0;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hProcessSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };

        if (Process32First(hProcessSnap, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                    processId = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }

    return processId;
}

// Define the packet queue and synchronization primitives
std::wstring ConvertToWideString(const std::string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}
std::string GetWorkingDirectory(const std::string& filePath) {
    size_t pos = filePath.find_last_of("\\/");
    return (pos == std::string::npos) ? "" : filePath.substr(0, pos);
}

std::string ExtractAppNameFromPath(const std::string& appPath) {
    size_t lastSlash = appPath.find_last_of("\\/");
    return lastSlash != std::string::npos ? appPath.substr(lastSlash + 1) : appPath;
}

bool IsLocalIp(const std::string& ip) {
    // Check for local IP addresses
    if (ip.find("127.") == 0 || ip.find("192.168.") == 0 ||
        ip.find("10.") == 0 || (ip.find("172.") == 0 && std::stoi(ip.substr(4, 2)) >= 16 && std::stoi(ip.substr(4, 2)) <= 31)) {
        return true;
    }
    return false;
}

PROCESS_INFORMATION g_processInfo = { 0 }; // Global process information

std::string GetErrorMessage(DWORD error) {
    LPVOID lpMsgBuf = nullptr;
    DWORD bufLen = FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf, 0, NULL);

    if (bufLen) {
        LPCSTR lpMsgStr = (LPCSTR)lpMsgBuf;
        std::string result(lpMsgStr, lpMsgStr + bufLen);

        LocalFree(lpMsgBuf);
        return result;
    }
    return "Unknown error.";
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    if (signal == CTRL_CLOSE_EVENT) {
        std::cout << "Console window is closing. Terminating target application..." << std::endl;
        if (g_processInfo.hProcess != NULL) {
            TerminateProcess(g_processInfo.hProcess, 0);
            CloseHandle(g_processInfo.hProcess);
            CloseHandle(g_processInfo.hThread);
            g_processInfo.hProcess = NULL;
            g_processInfo.hThread = NULL;
        }
    }
    return TRUE;
}

void MonitorProcessTermination(const TCHAR* processName) {
    while (keepMonitoringApplication.load()) {
        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create snapshot of processes" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }

        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hProcessSnap, &pe32)) {
            do {
                if (_tcsicmp(pe32.szExeFile, processName) == 0) {
                    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, pe32.th32ProcessID);
                    if (hProcess) {
                        DWORD waitResult = WaitForSingleObject(hProcess, INFINITE);
                        if (waitResult == WAIT_OBJECT_0) {
                            std::wcout << L"Process " << processName << L" terminated" << std::endl;
                            CloseHandle(hProcess);
                            keepMonitoringApplication.store(false);
                            break;
                        }
                        CloseHandle(hProcess);
                    }
                }
            } while (Process32Next(hProcessSnap, &pe32));
        }

        CloseHandle(hProcessSnap);
        std::this_thread::sleep_for(std::chrono::seconds(1)); // Avoid tight loop
    }
}

PROCESS_INFORMATION LaunchApplicationAndGetProcessInfo(const std::string& appPath, const std::string& workingDir) {
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi = { 0 }; // Initialize to zero

    std::wstring wideAppPath = ConvertToWideString(appPath); // Convert to wide string
    std::wstring wideWorkingDir = ConvertToWideString(workingDir); // Convert working directory to wide string

    if (!CreateProcess(
        wideAppPath.c_str(),    // Path to the application
        NULL,                   // Command line arguments
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        FALSE,                  // Set handle inheritance to FALSE
        0,                      // No creation flags
        NULL,                   // Use parent's environment block
        wideWorkingDir.c_str(), // Set working directory
        &si,                    // Pointer to STARTUPINFO structure
        &pi                     // Pointer to PROCESS_INFORMATION structure
    )) {
        std::cerr << "Failed to launch application: " << appPath << ". Error code: " << GetLastError() << std::endl;
        CloseHandle(pi.hProcess); // Ensure handle is closed if CreateProcess fails
        CloseHandle(pi.hThread);  // Ensure handle is closed if CreateProcess fails
        return {}; // Return an empty structure if the application failed to launch
    }

    g_processInfo = pi; // Store the process information globally

    return pi;
}

void UpdateJsonFile(const std::string& appPath, const std::unordered_set<std::string>& ipSet) {
    nlohmann::json jsonData;
    std::ifstream inputFile("network_monitor.json");

    // If the file exists, read its content
    if (inputFile.is_open()) {
        inputFile >> jsonData;
        inputFile.close();
    }

    // Update the JSON structure with application path and IP set
    std::string applicationName = "Application Name"; // Replace with actual application name if needed
    jsonData[applicationName]["Full Path"] = appPath;

    // Ensure the "IPs" array exists
    if (jsonData[applicationName]["IPs"].is_null()) {
        jsonData[applicationName]["IPs"] = nlohmann::json::array();
    }

    // Create a set from the existing IPs to avoid duplicates
    std::unordered_set<std::string> existingIps;
    for (const auto& ip : jsonData[applicationName]["IPs"]) {
        existingIps.insert(ip.get<std::string>());
    }

    // Add new IPs, avoiding duplicates
    for (const auto& ip : ipSet) {
        if (existingIps.find(ip) == existingIps.end()) {
            jsonData[applicationName]["IPs"].push_back(ip);
            existingIps.insert(ip);
        }
    }

    // Write the updated JSON to the file
    std::ofstream outputFile("network_monitor.json");
    if (outputFile.is_open()) {
        outputFile << std::setw(4) << jsonData << std::endl;
        outputFile.close();
    }
}

void MonitorLoadedModules(DWORD pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to create module snapshot for PID: " << pid << ". Error code: " << GetLastError() << std::endl;
        return;
    }

    MODULEENTRY32 me32{};
    me32.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(snapshot, &me32)) {
        do {
            // Convert WCHAR to char
            char moduleName[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, me32.szModule, -1, moduleName, MAX_PATH, NULL, NULL);
            std::cout << "Loaded module: " << moduleName << " in process: " << pid << std::endl;
        } while (Module32Next(snapshot, &me32));
    }

    CloseHandle(snapshot);
}