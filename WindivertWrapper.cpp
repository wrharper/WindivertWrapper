#include "WindivertWrapper.h"
#include <stdexcept>
#include <string>
#include <iostream>

WindivertWrapper g_windivertWrapper; // Define the global instance

WindivertWrapper::WindivertWrapper() : handle(INVALID_HANDLE_VALUE), hWinDivert(NULL) {
    try {
        LoadWinDivertFunctions();
    }
    catch (const std::exception& ex) {
        throw std::runtime_error("Exception during WindivertWrapper initialization: " + std::string(ex.what()));
    }
}

WindivertWrapper::~WindivertWrapper() {
    if (handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle);
        handle = INVALID_HANDLE_VALUE;
    }
    if (hWinDivert) {
        FreeLibrary(hWinDivert);
        hWinDivert = NULL;
    }
}

void WindivertWrapper::LoadWinDivertFunctions() {
    hWinDivert = LoadLibrary(TEXT("WinDivert.dll"));
    if (!hWinDivert) {
        DWORD error = GetLastError();
        throw std::runtime_error("Failed to load WinDivert.dll. Error: " + std::to_string(error));
    }

    WinDivertOpen = (WinDivertOpen_t)GetProcAddress(hWinDivert, "WinDivertOpen");
    WinDivertClose = (WinDivertClose_t)GetProcAddress(hWinDivert, "WinDivertClose");
    WinDivertRecv = (WinDivertRecv_t)GetProcAddress(hWinDivert, "WinDivertRecv");
    WinDivertRecvEx = (WinDivertRecvEx_t)GetProcAddress(hWinDivert, "WinDivertRecvEx");
    WinDivertSend = (WinDivertSend_t)GetProcAddress(hWinDivert, "WinDivertSend");
    WinDivertSendEx = (WinDivertSendEx_t)GetProcAddress(hWinDivert, "WinDivertSendEx");
    WinDivertShutdown = (WinDivertShutdown_t)GetProcAddress(hWinDivert, "WinDivertShutdown");
    WinDivertSetParam = (WinDivertSetParam_t)GetProcAddress(hWinDivert, "WinDivertSetParam");
    WinDivertGetParam = (WinDivertGetParam_t)GetProcAddress(hWinDivert, "WinDivertGetParam");

    if (!WinDivertOpen || !WinDivertClose || !WinDivertRecv || !WinDivertRecvEx || !WinDivertSend || !WinDivertSendEx || !WinDivertShutdown ||
        !WinDivertSetParam || !WinDivertGetParam) {
        throw std::runtime_error("Failed to load one or more WinDivert functions.");
    }

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

    if (!WinDivertHelperHashPacket || !WinDivertHelperParsePacket || !WinDivertHelperParseIPv4Address || !WinDivertHelperParseIPv6Address ||
        !WinDivertHelperFormatIPv4Address || !WinDivertHelperFormatIPv6Address || !WinDivertHelperCalcChecksums || !WinDivertHelperDecrementTTL ||
        !WinDivertHelperCompileFilter || !WinDivertHelperEvalFilter || !WinDivertHelperFormatFilter || !WinDivertHelperNtohs || !WinDivertHelperHtons ||
        !WinDivertHelperNtohl || !WinDivertHelperHtonl || !WinDivertHelperNtohll || !WinDivertHelperHtonll || !WinDivertHelperNtohIPv6Address ||
        !WinDivertHelperHtonIPv6Address) {
        throw std::runtime_error("Failed to load one or more WinDivert helper functions.");
    }
}

// Implement other methods...

HANDLE WindivertWrapper::Open(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags) {
    handle = WinDivertOpen(filter, layer, priority, flags);
    return handle;
}

BOOL WindivertWrapper::Close() {
    if (handle != INVALID_HANDLE_VALUE) {
        WinDivertClose(handle);
        handle = INVALID_HANDLE_VALUE;
    }
    return TRUE;
}

BOOL WindivertWrapper::Recv(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen) {
    if (handle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
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
    BOOL result = WinDivertHelperCompileFilter(filter, layer, object, objLen, errorStr, errorPos);
    if (!result && errorStr) {
        std::cerr << "HelperCompileFilter failed. Error: " << *errorStr << " at position: " << *errorPos << std::endl;
    }
    return result;
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
