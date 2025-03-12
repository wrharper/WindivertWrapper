// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H
// add headers that you want to pre-compile here
#include <mutex>
#include <iostream>
#include <unordered_set>
#include <string>
#include <condition_variable>
#include <atomic>
#include <thread>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <fstream>
#include <unordered_map>
#include <tchar.h>
#include "WindivertWrapper.h"
#include <TlHelp32.h>
#include <psapi.h> // Required for QueryFullProcessImageName
#include <iphlpapi.h>
#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable: 26819)
#pragma warning(disable: 26495)
#include <nlohmann/json.hpp>
#pragma warning(pop)
#endif

// Define the buffer size
constexpr auto PACKET_BUF_SIZE = 65535;

extern std::string appPath;
extern std::string workingDir;
std::string GetWorkingDirectory(const std::string& filePath);

#endif //PCH_H
