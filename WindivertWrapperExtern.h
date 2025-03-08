#pragma once

#ifdef WINDIVERTWRAPPER_EXPORTS
#define WINDIVERTWRAPPER_API __declspec(dllexport)
#else
#define WINDIVERTWRAPPER_API __declspec(dllimport)
#endif

#include <Windows.h>
#include "windivert.h"

extern "C" {
    WINDIVERTWRAPPER_API WindivertWrapper* CreateWindivertWrapperEx();
    WINDIVERTWRAPPER_API void DestroyWindivertWrapperEx(WindivertWrapper* instance);
    WINDIVERTWRAPPER_API HANDLE OpenEx(WindivertWrapper* instance, const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
    WINDIVERTWRAPPER_API BOOL CloseEx(WindivertWrapper* instance);
    WINDIVERTWRAPPER_API BOOL RecvEx(WindivertWrapper* instance, WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen);
    WINDIVERTWRAPPER_API BOOL RecvEx2(WindivertWrapper* instance, WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped);
    WINDIVERTWRAPPER_API BOOL SendEx(WindivertWrapper* instance, const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen);
    WINDIVERTWRAPPER_API BOOL SendEx2(WindivertWrapper* instance, const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped);
    WINDIVERTWRAPPER_API BOOL ShutdownEx(WindivertWrapper* instance, WINDIVERT_SHUTDOWN how);
    WINDIVERTWRAPPER_API BOOL SetParamEx(WindivertWrapper* instance, WINDIVERT_PARAM param, UINT64 value);
    WINDIVERTWRAPPER_API BOOL GetParamEx(WindivertWrapper* instance, WINDIVERT_PARAM param, UINT64* value);
    WINDIVERTWRAPPER_API UINT64 HelperHashPacketEx(WindivertWrapper* instance, const VOID* pPacket, UINT packetLen, UINT64 seed);
    WINDIVERTWRAPPER_API BOOL HelperParsePacketEx(WindivertWrapper* instance, const VOID* pPacket, UINT packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, UINT8* pProtocol,
        WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, PVOID** ppData, UINT* pDataLen);
    WINDIVERTWRAPPER_API BOOL HelperParseIPv4AddressEx(WindivertWrapper* instance, const char* addrStr, UINT32* pAddr);
    WINDIVERTWRAPPER_API BOOL HelperParseIPv6AddressEx(WindivertWrapper* instance, const char* addrStr, UINT32* pAddr);
    WINDIVERTWRAPPER_API BOOL HelperFormatIPv4AddressEx(WindivertWrapper* instance, UINT32 addr, char* buffer, UINT bufLen);
    WINDIVERTWRAPPER_API BOOL HelperFormatIPv6AddressEx(WindivertWrapper* instance, const UINT32* pAddr, char* buffer, UINT bufLen);
    WINDIVERTWRAPPER_API BOOL HelperCalcChecksumsEx(WindivertWrapper* instance, VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags);
    WINDIVERTWRAPPER_API BOOL HelperDecrementTTLEx(WindivertWrapper* instance, VOID* pPacket, UINT packetLen);
    WINDIVERTWRAPPER_API BOOL HelperCompileFilterEx(WindivertWrapper* instance, const char* filter, WINDIVERT_LAYER layer, char* object, UINT objLen, const char** errorStr, UINT* errorPos);
    WINDIVERTWRAPPER_API BOOL HelperEvalFilterEx(WindivertWrapper* instance, const char* filter, const VOID* pPacket, UINT packetLen, const WINDIVERT_ADDRESS* pAddr);
    WINDIVERTWRAPPER_API BOOL HelperFormatFilterEx(WindivertWrapper* instance, const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen);
    WINDIVERTWRAPPER_API UINT16 HelperNtohsEx(WindivertWrapper* instance, UINT16 x);
    WINDIVERTWRAPPER_API UINT16 HelperHtonsEx(WindivertWrapper* instance, UINT16 x);
    WINDIVERTWRAPPER_API UINT32 HelperNtohlEx(WindivertWrapper* instance, UINT32 x);
    WINDIVERTWRAPPER_API UINT32 HelperHtonlEx(WindivertWrapper* instance, UINT32 x);
    WINDIVERTWRAPPER_API UINT64 HelperNtohllEx(WindivertWrapper* instance, UINT64 x);
    WINDIVERTWRAPPER_API UINT64 HelperHtonllEx(WindivertWrapper* instance, UINT64 x);
    WINDIVERTWRAPPER_API void HelperNtohIPv6AddressEx(WindivertWrapper* instance, const UINT* inAddr, UINT* outAddr);
    WINDIVERTWRAPPER_API void HelperHtonIPv6AddressEx(WindivertWrapper* instance, const UINT* inAddr, UINT* outAddr);
}
