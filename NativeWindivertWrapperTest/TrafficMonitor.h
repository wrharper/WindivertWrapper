#include "pch.h"

constexpr auto ERRBUF_SIZE = 256; // Define a suitable error buffer size if PCAP_ERRBUF_SIZE is not available;

extern std::atomic<bool> keepMonitoringApplication;

std::string WideStringToUtf8(const std::wstring& wstr);
std::vector<DWORD> GetAllPidsByAppName(const std::string& appName);
std::string ConstructPidFilter(const std::vector<DWORD>& pids);
std::string GetApplicationNameFromPid(DWORD pid);
std::string ConvertIPv4ToString(ULONG ipAddress);
// Function declarations
DWORD GetProcessIdFromPacket(const WINDIVERT_ADDRESS& addr, const char* packet, UINT packetLen);
DWORD GetProcessIdFromPacket(const IPV4_HEADER* ipHeader);
void LaunchPowerShellScript(const std::string& scriptPath);
DWORD GetProcessIdByName(const std::wstring& processName);
std::wstring ConvertToWideString(const std::string& str);
std::string GetWorkingDirectory(const std::string& filePath);
std::string ExtractAppNameFromPath(const std::string& appPath);
bool IsLocalIp(const std::string& ip);
extern PROCESS_INFORMATION g_processInfo;
std::string GetErrorMessage(DWORD error);
PROCESS_INFORMATION LaunchApplicationAndGetProcessInfo(const std::string& appPath, const std::string& workingDir);
void MonitorProcessTermination(const TCHAR* processName);
BOOL WINAPI ConsoleHandler(DWORD signal);
void UpdateJsonFile(const std::string& appPath, const std::unordered_set<std::string>& ipSet);
void MonitorLoadedModules(DWORD pid);
//std::string ConvertIPv4ToString(UINT32 ipAddr);
//void MonitorChildProcesses(DWORD parentPid, std::vector<HANDLE>& divertHandles);