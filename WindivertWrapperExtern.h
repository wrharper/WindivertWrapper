#pragma once

#ifdef WINDIVERTWRAPPER_EXPORTS
#define WINDIVERTWRAPPER_API __declspec(dllexport)
#else
#define WINDIVERTWRAPPER_API __declspec(dllimport)
#endif

#include <Windows.h>
#include "windivert.h"
#include "WindivertWrapper.h" // Include the native wrapper header

class WINDIVERTWRAPPER_API WindivertWrapperEx {
public:
    HANDLE OpenEx(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
    BOOL CloseEx();
    BOOL RecvExx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen);
    BOOL RecvExEx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped);
    BOOL SendExx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen);
    BOOL SendExEx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped);
    BOOL ShutdownEx(WINDIVERT_SHUTDOWN how);
    BOOL SetParamEx(WINDIVERT_PARAM param, UINT64 value);
    BOOL GetParamEx(WINDIVERT_PARAM param, UINT64* value);

    // Helper functions
    UINT64 HelperHashPacketEx(const VOID* pPacket, UINT packetLen, UINT64 seed = 0);
    BOOL HelperParsePacketEx(const VOID* pPacket, UINT packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, UINT8* pProtocol,
        WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, PVOID** ppData,
        UINT* pDataLen);
    BOOL HelperParseIPv4AddressEx(const char* addrStr, UINT32* pAddr);
    BOOL HelperParseIPv6AddressEx(const char* addrStr, UINT32* pAddr);
    BOOL HelperFormatIPv4AddressEx(UINT32 addr, char* buffer, UINT bufLen);
    BOOL HelperFormatIPv6AddressEx(const UINT32* pAddr, char* buffer, UINT bufLen);
    BOOL HelperCalcChecksumsEx(VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags);
    BOOL HelperDecrementTTLEx(VOID* pPacket, UINT packetLen);
    BOOL HelperCompileFilterEx(const char* filter, WINDIVERT_LAYER layer, char* object, UINT objLen, const char** errorStr, UINT* errorPos);
    BOOL HelperEvalFilterEx(const char* filter, const VOID* pPacket, UINT packetLen, const WINDIVERT_ADDRESS* pAddr);
    BOOL HelperFormatFilterEx(const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen);

    UINT16 HelperNtohsEx(UINT16 x);
    UINT16 HelperHtonsEx(UINT16 x);
    UINT32 HelperNtohlEx(UINT32 x);
    UINT32 HelperHtonlEx(UINT32 x);
    UINT64 HelperNtohllEx(UINT64 x);
    UINT64 HelperHtonllEx(UINT64 x);
    void HelperNtohIPv6AddressEx(const UINT* inAddr, UINT* outAddr);
    void HelperHtonIPv6AddressEx(const UINT* inAddr, UINT* outAddr);
};
