#include "WindivertWrapper.h"
#include <iostream>
#include <stdexcept>
#include <string> // For std::to_string

WindivertWrapper::WindivertWrapper() : handle(INVALID_HANDLE_VALUE), hWinDivert(NULL) {
    std::cout << "Initializing WindivertWrapper" << std::endl;
    try {
        LoadWinDivertFunctions();
        std::cout << "WindivertWrapper initialized successfully" << std::endl;
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception during WindivertWrapper initialization: " << ex.what() << std::endl;
        throw; // Rethrow to indicate initialization failure
    }
}

WindivertWrapper::~WindivertWrapper() {
    if (handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle);
    }
    if (hWinDivert) {
        FreeLibrary(hWinDivert);
    }
}

void WindivertWrapper::LoadWinDivertFunctions() {
    std::cout << "Attempting to load WinDivert.dll" << std::endl;
    hWinDivert = LoadLibrary(TEXT("WinDivert.dll"));
    if (!hWinDivert) {
        DWORD error = GetLastError();
        throw std::runtime_error("Failed to load WinDivert.dll. Error: " + std::to_string(error));
    }
    std::cout << "Loaded WinDivert.dll" << std::endl;

    WinDivertOpen = (WinDivertOpen_t)GetProcAddress(hWinDivert, "WinDivertOpen");
    WinDivertClose = (WinDivertClose_t)GetProcAddress(hWinDivert, "WinDivertClose");
    WinDivertRecv = (WinDivertRecv_t)GetProcAddress(hWinDivert, "WinDivertRecv");
    WinDivertRecvEx = (WinDivertRecvEx_t)GetProcAddress(hWinDivert, "WinDivertRecvEx");
    WinDivertSend = (WinDivertSend_t)GetProcAddress(hWinDivert, "WinDivertSend");
    WinDivertSendEx = (WinDivertSendEx_t)GetProcAddress(hWinDivert, "WinDivertSendEx");
    WinDivertShutdown = (WinDivertShutdown_t)GetProcAddress(hWinDivert, "WinDivertShutdown");
    WinDivertSetParam = (WinDivertSetParam_t)GetProcAddress(hWinDivert, "WinDivertSetParam");
    WinDivertGetParam = (WinDivertGetParam_t)GetProcAddress(hWinDivert, "WinDivertGetParam");

    if (!WinDivertOpen) throw std::runtime_error("Failed to get WinDivertOpen address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertClose) throw std::runtime_error("Failed to get WinDivertClose address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertRecv) throw std::runtime_error("Failed to get WinDivertRecv address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertRecvEx) throw std::runtime_error("Failed to get WinDivertRecvEx address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertSend) throw std::runtime_error("Failed to get WinDivertSend address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertSendEx) throw std::runtime_error("Failed to get WinDivertSendEx address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertShutdown) throw std::runtime_error("Failed to get WinDivertShutdown address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertSetParam) throw std::runtime_error("Failed to get WinDivertSetParam address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertGetParam) throw std::runtime_error("Failed to get WinDivertGetParam address. Error: " + std::to_string(GetLastError()));

    WinDivertHelperHashPacket = (WinDivertHelperHashPacket_t)GetProcAddress(hWinDivert, "WinDivertHelperHashPacket");
    WinDivertHelperParsePacket = (WinDivertHelperParsePacket_t)GetProcAddress(hWinDivert, "WinDivertHelperParsePacket");
    WinDivertHelperParseIPv4Address = (WinDivertHelperParseIPv4Address_t)GetProcAddress(hWinDivert, "WinDivertHelperParseIPv4Address");
    WinDivertHelperParseIPv6Address = (WinDivertHelperParseIPv6Address_t)GetProcAddress(hWinDivert, "WinDivertHelperParseIPv6Address");
    WinDivertHelperFormatIPv4Address = (WinDivertHelperFormatIPv4Address_t)GetProcAddress(hWinDivert, "WinDivertHelperFormatIPv4Address");
    WinDivertHelperFormatIPv6Address = (WinDivertHelperFormatIPv6Address_t)GetProcAddress(hWinDivert, "WinDivertHelperFormatIPv6Address");
    WinDivertHelperCalcChecksums = (WinDivertHelperCalcChecksums_t)GetProcAddress(hWinDivert, "WinDivertHelperCalcChecksums");
    WinDivertHelperDecrementTTL = (WinDivertHelperDecrementTTL_t)GetProcAddress(hWinDivert, "WinDivertHelperDecrementTTL");
    WinDivertHelperCompileFilter = (WinDivertHelperCompileFilter_t)GetProcAddress(hWinDivert, "WinDivertHelperCompileFilter");
    WinDivertHelperEvalFilter = (WinDivertHelperEvalFilter_t)GetProcAddress(hWinDivert, "WinDivertHelperEvalFilter");
    WinDivertHelperFormatFilter = (WinDivertHelperFormatFilter_t)GetProcAddress(hWinDivert, "WinDivertHelperFormatFilter");

    WinDivertHelperNtohs = (WinDivertHelperNtohs_t)GetProcAddress(hWinDivert, "WinDivertHelperNtohs");
    WinDivertHelperHtons = (WinDivertHelperHtons_t)GetProcAddress(hWinDivert, "WinDivertHelperHtons");
    WinDivertHelperNtohl = (WinDivertHelperNtohl_t)GetProcAddress(hWinDivert, "WinDivertHelperNtohl");
    WinDivertHelperHtonl = (WinDivertHelperHtonl_t)GetProcAddress(hWinDivert, "WinDivertHelperHtonl");
    WinDivertHelperNtohll = (WinDivertHelperNtohll_t)GetProcAddress(hWinDivert, "WinDivertHelperNtohll");
    WinDivertHelperHtonll = (WinDivertHelperHtonll_t)GetProcAddress(hWinDivert, "WinDivertHelperHtonll");
    WinDivertHelperNtohIPv6Address = (WinDivertHelperNtohIPv6Address_t)GetProcAddress(hWinDivert, "WinDivertHelperNtohIPv6Address");
    WinDivertHelperHtonIPv6Address = (WinDivertHelperHtonIPv6Address_t)GetProcAddress(hWinDivert, "WinDivertHelperHtonIPv6Address");

    if (!WinDivertHelperHashPacket) throw std::runtime_error("Failed to get WinDivertHelperHashPacket address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperParsePacket) throw std::runtime_error("Failed to get WinDivertHelperParsePacket address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperParseIPv4Address) throw std::runtime_error("Failed to get WinDivertHelperParseIPv4Address address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperParseIPv6Address) throw std::runtime_error("Failed to get WinDivertHelperParseIPv6Address address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperFormatIPv4Address) throw std::runtime_error("Failed to get WinDivertHelperFormatIPv4Address address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperFormatIPv6Address) throw std::runtime_error("Failed to get WinDivertHelperFormatIPv6Address address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperCalcChecksums) throw std::runtime_error("Failed to get WinDivertHelperCalcChecksums address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperDecrementTTL) throw std::runtime_error("Failed to get WinDivertHelperDecrementTTL address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperCompileFilter) throw std::runtime_error("Failed to get WinDivertHelperCompileFilter address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperEvalFilter) throw std::runtime_error("Failed to get WinDivertHelperEvalFilter address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperFormatFilter) throw std::runtime_error("Failed to get WinDivertHelperFormatFilter address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperNtohs) throw std::runtime_error("Failed to get WinDivertHelperNtohs address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperHtons) throw std::runtime_error("Failed to get WinDivertHelperHtons address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperNtohl) throw std::runtime_error("Failed to get WinDivertHelperNtohl address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperHtonl) throw std::runtime_error("Failed to get WinDivertHelperHtonl address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperNtohll) throw std::runtime_error("Failed to get WinDivertHelperNtohll address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperHtonll) throw std::runtime_error("Failed to get WinDivertHelperHtonll address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperNtohIPv6Address) throw std::runtime_error("Failed to get WinDivertHelperNtohIPv6Address address. Error: " + std::to_string(GetLastError()));
    if (!WinDivertHelperHtonIPv6Address) throw std::runtime_error("Failed to get WinDivertHelperHtonIPv6Address address. Error: " + std::to_string(GetLastError()));

    std::cout << "WinDivert functions loaded successfully" << std::endl;
}

HANDLE WindivertWrapper::Open(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags) {
    std::cout << "Opening WinDivert with filter: " << filter << ", layer: " << layer << ", priority: " << priority << ", flags: " << flags << std::endl;
    HANDLE handle = WinDivertOpen(filter, layer, priority, flags);
    if (handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        std::cerr << "WinDivertOpen failed. Error: " << std::to_string(static_cast<unsigned long long>(error)) << std::endl;
    }
    else {
        std::cout << "WinDivertOpen succeeded. Handle: " << handle << std::endl;
    }
    return handle;
}

BOOL WindivertWrapper::Close() {
    if (handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle);
        handle = INVALID_HANDLE_VALUE;
        std::cout << "WinDivert handle closed successfully." << std::endl;
    }
    return TRUE;
}

BOOL WindivertWrapper::Recv(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen) {
    return WinDivertRecv(handle, packet, packetLen, recvLen, address);
}

BOOL WindivertWrapper::RecvEx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped) {
    return WinDivertRecvEx(handle, packet, packetLen, recvLen, flags, address, addrLen, lpOverlapped);
}

BOOL WindivertWrapper::Send(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen) {
    return WinDivertSend(handle, packet, packetLen, sendLen, address);
}

BOOL WindivertWrapper::SendEx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped) {
    return WinDivertSendEx(handle, packet, packetLen, sendLen, flags, address, addrLen, lpOverlapped);
}

BOOL WindivertWrapper::Shutdown(WINDIVERT_SHUTDOWN how) {
    return WinDivertShutdown(handle, how);
}

BOOL WindivertWrapper::SetParam(WINDIVERT_PARAM param, UINT64 value) {
    return WinDivertSetParam(handle, param, value);
}

BOOL WindivertWrapper::GetParam(WINDIVERT_PARAM param, UINT64* value) {
    return WinDivertGetParam(handle, param, value);
}

// Implementations for the helper functions

UINT64 WindivertWrapper::HelperHashPacket(const VOID* pPacket, UINT packetLen, UINT64 seed) {
    return WinDivertHelperHashPacket(pPacket, packetLen, seed);
}

BOOL WindivertWrapper::HelperParsePacket(const VOID* pPacket, UINT packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, UINT8* pProtocol,
    WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, PVOID** ppData,
    UINT* pDataLen) {
    return WinDivertHelperParsePacket(pPacket, packetLen, ppIpHdr, ppIpv6Hdr, pProtocol, ppIcmpHdr, ppIcmpv6Hdr, ppTcpHdr, ppUdpHdr, ppData, pDataLen);
}

BOOL WindivertWrapper::HelperParseIPv4Address(const char* addrStr, UINT32* pAddr) {
    return WinDivertHelperParseIPv4Address(addrStr, pAddr);
}

BOOL WindivertWrapper::HelperParseIPv6Address(const char* addrStr, UINT32* pAddr) {
    return WinDivertHelperParseIPv6Address(addrStr, pAddr);
}

BOOL WindivertWrapper::HelperFormatIPv4Address(UINT32 addr, char* buffer, UINT bufLen) {
    return WinDivertHelperFormatIPv4Address(addr, buffer, bufLen);
}

BOOL WindivertWrapper::HelperFormatIPv6Address(const UINT32* pAddr, char* buffer, UINT bufLen) {
    return WinDivertHelperFormatIPv6Address(pAddr, buffer, bufLen);
}

BOOL WindivertWrapper::HelperCalcChecksums(VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags) {
    return WinDivertHelperCalcChecksums(pPacket, packetLen, pAddr, flags);
}

BOOL WindivertWrapper::HelperDecrementTTL(VOID* pPacket, UINT packetLen) {
    return WinDivertHelperDecrementTTL(pPacket, packetLen);
}

BOOL WindivertWrapper::HelperCompileFilter(const char* filter, WINDIVERT_LAYER layer, char* object, UINT objLen, const char** errorStr, UINT* errorPos) {
    return WinDivertHelperCompileFilter(filter, layer, object, objLen, errorStr, errorPos);
}

BOOL WindivertWrapper::HelperEvalFilter(const char* filter, const VOID* pPacket, UINT packetLen, const WINDIVERT_ADDRESS* pAddr) {
    return WinDivertHelperEvalFilter(filter, pPacket, packetLen, pAddr);
}

BOOL WindivertWrapper::HelperFormatFilter(const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen) {
    return WinDivertHelperFormatFilter(filter, layer, buffer, bufLen);
}

UINT16 WindivertWrapper::HelperNtohs(UINT16 x) {
    return WinDivertHelperNtohs(x);
}

UINT16 WindivertWrapper::HelperHtons(UINT16 x) {
    return WinDivertHelperHtons(x);
}

UINT32 WindivertWrapper::HelperNtohl(UINT32 x) {
    return WinDivertHelperNtohl(x);
}

UINT32 WindivertWrapper::HelperHtonl(UINT32 x) {
    return WinDivertHelperHtonl(x);
}

UINT64 WindivertWrapper::HelperNtohll(UINT64 x) {
    return WinDivertHelperNtohll(x);
}

UINT64 WindivertWrapper::HelperHtonll(UINT64 x) {
    return WinDivertHelperHtonll(x);
}

void WindivertWrapper::HelperNtohIPv6Address(const UINT* inAddr, UINT* outAddr) {
    WinDivertHelperNtohIPv6Address(inAddr, outAddr);
}

void WindivertWrapper::HelperHtonIPv6Address(const UINT* inAddr, UINT* outAddr) {
    WinDivertHelperHtonIPv6Address(inAddr, outAddr);
}
