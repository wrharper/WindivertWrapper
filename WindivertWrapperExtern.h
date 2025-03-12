#pragma once

#ifdef WINDIVERTWRAPPER_EXPORTS
#define WINDIVERTWRAPPER_API __declspec(dllexport)
#else
#define WINDIVERTWRAPPER_API __declspec(dllimport)
#endif

#define WIN32_LEAN_AND_MEAN
#include "WindivertWrapper.h" // Include the native wrapper header

extern "C" {
    __declspec(dllexport) HANDLE Open(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
    __declspec(dllexport) BOOL Close();
    __declspec(dllexport) BOOL Recv(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen);
    __declspec(dllexport) BOOL RecvEx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped);
    __declspec(dllexport) BOOL Send(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen);
    __declspec(dllexport) BOOL SendEx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped);
    __declspec(dllexport) BOOL Shutdown(WINDIVERT_SHUTDOWN how);
    __declspec(dllexport) BOOL SetParam(WINDIVERT_PARAM param, UINT64 value);
    __declspec(dllexport) BOOL GetParam(WINDIVERT_PARAM param, UINT64* value);

    // Helper functions
    __declspec(dllexport) UINT64 HelperHashPacket(const VOID* pPacket, UINT packetLen, UINT64 seed = 0);
    __declspec(dllexport) BOOL HelperParsePacket(const VOID* pPacket, UINT packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, UINT8* pProtocol,
        WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, PVOID** ppData,
        UINT* pDataLen);
    __declspec(dllexport) BOOL HelperParseIPv4Address(const char* addrStr, UINT32* pAddr);
    __declspec(dllexport) BOOL HelperParseIPv6Address(const char* addrStr, UINT32* pAddr);
    __declspec(dllexport) BOOL HelperFormatIPv4Address(UINT32 addr, char* buffer, UINT bufLen);
    __declspec(dllexport) BOOL HelperFormatIPv6Address(const UINT32* pAddr, char* buffer, UINT bufLen);
    __declspec(dllexport) BOOL HelperCalcChecksums(VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags);
    __declspec(dllexport) BOOL HelperDecrementTTL(VOID* pPacket, UINT packetLen);
    __declspec(dllexport) BOOL HelperCompileFilter(const char* filter, WINDIVERT_LAYER layer, char* object, UINT objLen, const char** errorStr, UINT* errorPos);
    __declspec(dllexport) BOOL HelperEvalFilter(const char* filter, const VOID* pPacket, UINT packetLen, const WINDIVERT_ADDRESS* pAddr);
    __declspec(dllexport) BOOL HelperFormatFilter(const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen);

    __declspec(dllexport) UINT16 HelperNtohs(UINT16 x);
    __declspec(dllexport) UINT16 HelperHtons(UINT16 x);
    __declspec(dllexport) UINT32 HelperNtohl(UINT32 x);
    __declspec(dllexport) UINT32 HelperHtonl(UINT32 x);
    __declspec(dllexport) UINT64 HelperNtohll(UINT64 x);
    __declspec(dllexport) UINT64 HelperHtonll(UINT64 x);
    __declspec(dllexport) void HelperNtohIPv6Address(const UINT* inAddr, UINT* outAddr);
    __declspec(dllexport) void HelperHtonIPv6Address(const UINT* inAddr, UINT* outAddr);
}
