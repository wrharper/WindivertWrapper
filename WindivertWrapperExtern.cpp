#include "WindivertWrapper.h"

extern "C" {
    // Constructor and Destructor
    WINDIVERTWRAPPER_API WindivertWrapper* CreateWindivertWrapperEx() {
        return new WindivertWrapper();
    }

    WINDIVERTWRAPPER_API void DestroyWindivertWrapperEx(WindivertWrapper* instance) {
        delete instance;
    }

    // Methods
    WINDIVERTWRAPPER_API HANDLE OpenEx(WindivertWrapper* instance, const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags) {
        return instance->Open(filter, layer, priority, flags);
    }

    WINDIVERTWRAPPER_API BOOL CloseEx(WindivertWrapper* instance) {
        return instance->Close();
    }

    WINDIVERTWRAPPER_API BOOL RecvEx(WindivertWrapper* instance, WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen) {
        return instance->Recv(address, packet, packetLen, recvLen);
    }

    WINDIVERTWRAPPER_API BOOL RecvEx2(WindivertWrapper* instance, WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped) {
        return instance->RecvEx(address, packet, packetLen, recvLen, flags, addrLen, lpOverlapped);
    }

    WINDIVERTWRAPPER_API BOOL SendEx(WindivertWrapper* instance, const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen) {
        return instance->Send(address, packet, packetLen, sendLen);
    }

    WINDIVERTWRAPPER_API BOOL SendEx2(WindivertWrapper* instance, const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped) {
        return instance->SendEx(address, packet, packetLen, sendLen, flags, addrLen, lpOverlapped);
    }

    WINDIVERTWRAPPER_API BOOL ShutdownEx(WindivertWrapper* instance, WINDIVERT_SHUTDOWN how) {
        return instance->Shutdown(how);
    }

    WINDIVERTWRAPPER_API BOOL SetParamEx(WindivertWrapper* instance, WINDIVERT_PARAM param, UINT64 value) {
        return instance->SetParam(param, value);
    }

    WINDIVERTWRAPPER_API BOOL GetParamEx(WindivertWrapper* instance, WINDIVERT_PARAM param, UINT64* value) {
        return instance->GetParam(param, value);
    }

    // Helper Functions
    WINDIVERTWRAPPER_API UINT64 HelperHashPacketEx(WindivertWrapper* instance, const VOID* pPacket, UINT packetLen, UINT64 seed) {
        return instance->HelperHashPacket(pPacket, packetLen, seed);
    }

    WINDIVERTWRAPPER_API BOOL HelperParsePacketEx(WindivertWrapper* instance, const VOID* pPacket, UINT packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, UINT8* pProtocol,
        WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, PVOID** ppData, UINT* pDataLen) {
        return instance->HelperParsePacket(pPacket, packetLen, ppIpHdr, ppIpv6Hdr, pProtocol, ppIcmpHdr, ppIcmpv6Hdr, ppTcpHdr, ppUdpHdr, ppData, pDataLen);
    }

    WINDIVERTWRAPPER_API BOOL HelperParseIPv4AddressEx(WindivertWrapper* instance, const char* addrStr, UINT32* pAddr) {
        return instance->HelperParseIPv4Address(addrStr, pAddr);
    }

    WINDIVERTWRAPPER_API BOOL HelperParseIPv6AddressEx(WindivertWrapper* instance, const char* addrStr, UINT32* pAddr) {
        return instance->HelperParseIPv6Address(addrStr, pAddr);
    }

    WINDIVERTWRAPPER_API BOOL HelperFormatIPv4AddressEx(WindivertWrapper* instance, UINT32 addr, char* buffer, UINT bufLen) {
        return instance->HelperFormatIPv4Address(addr, buffer, bufLen);
    }

    WINDIVERTWRAPPER_API BOOL HelperFormatIPv6AddressEx(WindivertWrapper* instance, const UINT32* pAddr, char* buffer, UINT bufLen) {
        return instance->HelperFormatIPv6Address(pAddr, buffer, bufLen);
    }

    WINDIVERTWRAPPER_API BOOL HelperCalcChecksumsEx(WindivertWrapper* instance, VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags) {
        return instance->HelperCalcChecksums(pPacket, packetLen, pAddr, flags);
    }

    WINDIVERTWRAPPER_API BOOL HelperDecrementTTLEx(WindivertWrapper* instance, VOID* pPacket, UINT packetLen) {
        return instance->HelperDecrementTTL(pPacket, packetLen);
    }

    WINDIVERTWRAPPER_API BOOL HelperCompileFilterEx(WindivertWrapper* instance, const char* filter, WINDIVERT_LAYER layer, char* object, UINT objLen, const char** errorStr, UINT* errorPos) {
        return instance->HelperCompileFilter(filter, layer, object, objLen, errorStr, errorPos);
    }

    WINDIVERTWRAPPER_API BOOL HelperEvalFilterEx(WindivertWrapper* instance, const char* filter, const VOID* pPacket, UINT packetLen, const WINDIVERT_ADDRESS* pAddr) {
        return instance->HelperEvalFilter(filter, pPacket, packetLen, pAddr);
    }

    WINDIVERTWRAPPER_API BOOL HelperFormatFilterEx(WindivertWrapper* instance, const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen) {
        return instance->HelperFormatFilter(filter, layer, buffer, bufLen);
    }

    WINDIVERTWRAPPER_API UINT16 HelperNtohsEx(WindivertWrapper* instance, UINT16 x) {
        return instance->HelperNtohs(x);
    }

    WINDIVERTWRAPPER_API UINT16 HelperHtonsEx(WindivertWrapper* instance, UINT16 x) {
        return instance->HelperHtons(x);
    }

    WINDIVERTWRAPPER_API UINT32 HelperNtohlEx(WindivertWrapper* instance, UINT32 x) {
        return instance->HelperNtohl(x);
    }

    WINDIVERTWRAPPER_API UINT32 HelperHtonlEx(WindivertWrapper* instance, UINT32 x) {
        return instance->HelperHtonl(x);
    }

    WINDIVERTWRAPPER_API UINT64 HelperNtohllEx(WindivertWrapper* instance, UINT64 x) {
        return instance->HelperNtohll(x);
    }

    WINDIVERTWRAPPER_API UINT64 HelperHtonllEx(WindivertWrapper* instance, UINT64 x) {
        return instance->HelperHtonll(x);
    }

    WINDIVERTWRAPPER_API void HelperNtohIPv6AddressEx(WindivertWrapper* instance, const UINT* inAddr, UINT* outAddr) {
        instance->HelperNtohIPv6Address(inAddr, outAddr);
    }

    WINDIVERTWRAPPER_API void HelperHtonIPv6AddressEx(WindivertWrapper* instance, const UINT* inAddr, UINT* outAddr) {
        instance->HelperHtonIPv6Address(inAddr, outAddr);
    }
}
