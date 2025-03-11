#pragma once

#ifdef WINDIVERTWRAPPER_EXPORTS
#define WINDIVERTWRAPPER_API __declspec(dllexport)
#else
#define WINDIVERTWRAPPER_API __declspec(dllimport)
#endif

#define WIN32_LEAN_AND_MEAN
#include "WindivertWrapper.h" // Include the native wrapper header

extern "C" {
    __declspec(dllexport) HANDLE OpenRecvEx(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
    __declspec(dllexport) HANDLE OpenSendEx(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
    __declspec(dllexport) BOOL CloseRecvEx();
    __declspec(dllexport) BOOL CloseSendEx();
    __declspec(dllexport) BOOL RecvExx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen);
    __declspec(dllexport) BOOL RecvExEx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped);
    __declspec(dllexport) BOOL SendExx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen);
    __declspec(dllexport) BOOL SendExEx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped);
    __declspec(dllexport) BOOL ShutdownEx(WINDIVERT_SHUTDOWN how);
    __declspec(dllexport) BOOL SetParamEx(WINDIVERT_PARAM param, UINT64 value);
    __declspec(dllexport) BOOL GetParamEx(WINDIVERT_PARAM param, UINT64* value);

    // Helper functions
    __declspec(dllexport) UINT64 HelperHashPacketEx(const VOID* pPacket, UINT packetLen, UINT64 seed = 0);
    __declspec(dllexport) BOOL HelperParsePacketEx(const VOID* pPacket, UINT packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, UINT8* pProtocol,
        WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, PVOID** ppData,
        UINT* pDataLen);
    __declspec(dllexport) BOOL HelperParseIPv4AddressEx(const char* addrStr, UINT32* pAddr);
    __declspec(dllexport) BOOL HelperParseIPv6AddressEx(const char* addrStr, UINT32* pAddr);
    __declspec(dllexport) BOOL HelperFormatIPv4AddressEx(UINT32 addr, char* buffer, UINT bufLen);
    __declspec(dllexport) BOOL HelperFormatIPv6AddressEx(const UINT32* pAddr, char* buffer, UINT bufLen);
    __declspec(dllexport) BOOL HelperCalcChecksumsEx(VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags);
    __declspec(dllexport) BOOL HelperDecrementTTLEx(VOID* pPacket, UINT packetLen);
    __declspec(dllexport) BOOL HelperCompileFilterEx(const char* filter, WINDIVERT_LAYER layer, char* object, UINT objLen, const char** errorStr, UINT* errorPos);
    __declspec(dllexport) BOOL HelperEvalFilterEx(const char* filter, const VOID* pPacket, UINT packetLen, const WINDIVERT_ADDRESS* pAddr);
    __declspec(dllexport) BOOL HelperFormatFilterEx(const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen);

    __declspec(dllexport) UINT16 HelperNtohsEx(UINT16 x);
    __declspec(dllexport) UINT16 HelperHtonsEx(UINT16 x);
    __declspec(dllexport) UINT32 HelperNtohlEx(UINT32 x);
    __declspec(dllexport) UINT32 HelperHtonlEx(UINT32 x);
    __declspec(dllexport) UINT64 HelperNtohllEx(UINT64 x);
    __declspec(dllexport) UINT64 HelperHtonllEx(UINT64 x);
    __declspec(dllexport) void HelperNtohIPv6AddressEx(const UINT* inAddr, UINT* outAddr);
    __declspec(dllexport) void HelperHtonIPv6AddressEx(const UINT* inAddr, UINT* outAddr);
}
