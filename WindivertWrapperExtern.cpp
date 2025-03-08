#include "WindivertWrapperExtern.h"
#include "WindivertWrapper.h"
#include <stdexcept>
#include <string>
#include <iostream>

// Referencing the global instance declared in WindivertWrapper.cpp
extern WindivertWrapper g_windivertWrapper;

HANDLE WindivertWrapperEx::OpenEx(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags) {
    return g_windivertWrapper.Open(filter, layer, priority, flags);
}

BOOL WindivertWrapperEx::CloseEx() {
    return g_windivertWrapper.Close();
}

BOOL WindivertWrapperEx::RecvExx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen) {
    return g_windivertWrapper.Recv(address, packet, packetLen, recvLen);
}

BOOL WindivertWrapperEx::RecvExEx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped) {
    return g_windivertWrapper.RecvEx(address, packet, packetLen, recvLen, flags, addrLen, lpOverlapped);
}

BOOL WindivertWrapperEx::SendExx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen) {
    return g_windivertWrapper.Send(address, packet, packetLen, sendLen);
}

BOOL WindivertWrapperEx::SendExEx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped) {
    return g_windivertWrapper.SendEx(address, packet, packetLen, sendLen, flags, addrLen, lpOverlapped);
}

BOOL WindivertWrapperEx::ShutdownEx(WINDIVERT_SHUTDOWN how) {
    return g_windivertWrapper.Shutdown(how);
}

BOOL WindivertWrapperEx::SetParamEx(WINDIVERT_PARAM param, UINT64 value) {
    return g_windivertWrapper.SetParam(param, value);
}

BOOL WindivertWrapperEx::GetParamEx(WINDIVERT_PARAM param, UINT64* value) {
    return g_windivertWrapper.GetParam(param, value);
}

UINT64 WindivertWrapperEx::HelperHashPacketEx(const VOID* pPacket, UINT packetLen, UINT64 seed) {
    return g_windivertWrapper.HelperHashPacket(pPacket, packetLen, seed);
}

BOOL WindivertWrapperEx::HelperParsePacketEx(const VOID* pPacket, UINT packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, UINT8* pProtocol,
    WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, PVOID** ppData,
    UINT* pDataLen) {
    return g_windivertWrapper.HelperParsePacket(pPacket, packetLen, ppIpHdr, ppIpv6Hdr, pProtocol, ppIcmpHdr, ppIcmpv6Hdr, ppTcpHdr, ppUdpHdr, ppData, pDataLen);
}

BOOL WindivertWrapperEx::HelperParseIPv4AddressEx(const char* addrStr, UINT32* pAddr) {
    return g_windivertWrapper.HelperParseIPv4Address(addrStr, pAddr);
}

BOOL WindivertWrapperEx::HelperParseIPv6AddressEx(const char* addrStr, UINT32* pAddr) {
    return g_windivertWrapper.HelperParseIPv6Address(addrStr, pAddr);
}

BOOL WindivertWrapperEx::HelperFormatIPv4AddressEx(UINT32 addr, char* buffer, UINT bufLen) {
    return g_windivertWrapper.HelperFormatIPv4Address(addr, buffer, bufLen);
}

BOOL WindivertWrapperEx::HelperFormatIPv6AddressEx(const UINT32* pAddr, char* buffer, UINT bufLen) {
    return g_windivertWrapper.HelperFormatIPv6Address(pAddr, buffer, bufLen);
}

BOOL WindivertWrapperEx::HelperCalcChecksumsEx(VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags) {
    return g_windivertWrapper.HelperCalcChecksums(pPacket, packetLen, pAddr, flags);
}

BOOL WindivertWrapperEx::HelperDecrementTTLEx(VOID* pPacket, UINT packetLen) {
    return g_windivertWrapper.HelperDecrementTTL(pPacket, packetLen);
}

BOOL WindivertWrapperEx::HelperCompileFilterEx(const char* filter, WINDIVERT_LAYER layer, char* object, UINT objLen, const char** errorStr, UINT* errorPos) {
    BOOL result = g_windivertWrapper.HelperCompileFilter(filter, layer, object, objLen, errorStr, errorPos);
    if (!result && errorStr) {
        std::cerr << "HelperCompileFilterEx failed. Error: " << *errorStr << " at position: " << *errorPos << std::endl;
    }
    return result;
}

BOOL WindivertWrapperEx::HelperEvalFilterEx(const char* filter, const VOID* pPacket, UINT packetLen, const WINDIVERT_ADDRESS* pAddr) {
    return g_windivertWrapper.HelperEvalFilter(filter, pPacket, packetLen, pAddr);
}

BOOL WindivertWrapperEx::HelperFormatFilterEx(const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen) {
    return g_windivertWrapper.HelperFormatFilter(filter, layer, buffer, bufLen);
}

UINT16 WindivertWrapperEx::HelperNtohsEx(UINT16 x) {
    return g_windivertWrapper.HelperNtohs(x);
}

UINT16 WindivertWrapperEx::HelperHtonsEx(UINT16 x) {
    return g_windivertWrapper.HelperHtons(x);
}

UINT32 WindivertWrapperEx::HelperNtohlEx(UINT32 x) {
    return g_windivertWrapper.HelperNtohl(x);
}

UINT32 WindivertWrapperEx::HelperHtonlEx(UINT32 x) {
    return g_windivertWrapper.HelperHtonl(x);
}

UINT64 WindivertWrapperEx::HelperNtohllEx(UINT64 x) {
    return g_windivertWrapper.HelperNtohll(x);
}

UINT64 WindivertWrapperEx::HelperHtonllEx(UINT64 x) {
    return g_windivertWrapper.HelperHtonll(x);
}

void WindivertWrapperEx::HelperNtohIPv6AddressEx(const UINT* inAddr, UINT* outAddr) {
    g_windivertWrapper.HelperNtohIPv6Address(inAddr, outAddr);
}

void WindivertWrapperEx::HelperHtonIPv6AddressEx(const UINT* inAddr, UINT* outAddr) {
    g_windivertWrapper.HelperHtonIPv6Address(inAddr, outAddr);
}
