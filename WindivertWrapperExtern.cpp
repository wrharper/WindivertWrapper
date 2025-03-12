#include "WindivertWrapperExtern.h"

// Create a single local instance of WindivertWrapper
static WindivertWrapper divertInstance;

extern "C" {
    __declspec(dllexport) HANDLE Open(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags) {
        return divertInstance.Open(filter, layer, priority, flags);
    }

    __declspec(dllexport) BOOL Close() {
        return divertInstance.Close();
    }

    __declspec(dllexport) BOOL Recv(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen) {
        return divertInstance.Recv(address, packet, packetLen, recvLen);
    }

    __declspec(dllexport) BOOL RecvEx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped) {
        return divertInstance.RecvEx(address, packet, packetLen, recvLen, flags, addrLen, lpOverlapped);
    }

    __declspec(dllexport) BOOL Send(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen) {
        return divertInstance.Send(address, packet, packetLen, sendLen);
    }

    __declspec(dllexport) BOOL SendEx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped) {
        return divertInstance.SendEx(address, packet, packetLen, sendLen, flags, addrLen, lpOverlapped);
    }

    __declspec(dllexport) BOOL Shutdown(WINDIVERT_SHUTDOWN how) {
        return divertInstance.Shutdown(how);
    }

    __declspec(dllexport) BOOL SetParam(WINDIVERT_PARAM param, UINT64 value) {
        return divertInstance.SetParam(param, value);
    }

    __declspec(dllexport) BOOL GetParam(WINDIVERT_PARAM param, UINT64* value) {
        return divertInstance.GetParam(param, value);
    }

    __declspec(dllexport) UINT64 HelperHashPacket(const VOID* packet, UINT packetLen, UINT64 seed) {
        return divertInstance.HelperHashPacket(packet, packetLen, seed);
    }

    __declspec(dllexport) BOOL HelperParsePacket(const VOID* packet, UINT packetLen, WINDIVERT_IPHDR** ipHdr, WINDIVERT_IPV6HDR** ipv6Hdr, UINT8* protocol,
        WINDIVERT_ICMPHDR** icmpHdr, WINDIVERT_ICMPV6HDR** icmpv6Hdr, WINDIVERT_TCPHDR** tcpHdr, WINDIVERT_UDPHDR** udpHdr, PVOID** data, UINT* dataLen) {
        return divertInstance.HelperParsePacket(packet, packetLen, ipHdr, ipv6Hdr, protocol, icmpHdr, icmpv6Hdr, tcpHdr, udpHdr, data, dataLen);
    }

    __declspec(dllexport) BOOL HelperParseIPv4Address(const char* addrStr, UINT32* addr) {
        return divertInstance.HelperParseIPv4Address(addrStr, addr);
    }

    __declspec(dllexport) BOOL HelperParseIPv6Address(const char* addrStr, UINT32* addr) {
        return divertInstance.HelperParseIPv6Address(addrStr, addr);
    }

    __declspec(dllexport) BOOL HelperFormatIPv4Address(UINT32 addr, char* buffer, UINT bufLen) {
        return divertInstance.HelperFormatIPv4Address(addr, buffer, bufLen);
    }

    __declspec(dllexport) BOOL HelperFormatIPv6Address(const UINT32* addr, char* buffer, UINT bufLen) {
        return divertInstance.HelperFormatIPv6Address(addr, buffer, bufLen);
    }

    __declspec(dllexport) BOOL HelperCalcChecksums(VOID* packet, UINT packetLen, WINDIVERT_ADDRESS* address, UINT64 flags) {
        return divertInstance.HelperCalcChecksums(packet, packetLen, address, flags);
    }

    __declspec(dllexport) BOOL HelperDecrementTTL(VOID* packet, UINT packetLen) {
        return divertInstance.HelperDecrementTTL(packet, packetLen);
    }

    __declspec(dllexport) BOOL HelperCompileFilter(const char* filter, WINDIVERT_LAYER layer, char* objectBuffer, UINT objLen, const char** errorStr, UINT* errorPos) {
        BOOL result = divertInstance.HelperCompileFilter(filter, layer, objectBuffer, objLen, errorStr, errorPos);
        if (!result && errorStr) {
            std::cerr << "HelperCompileFilterEx failed. Error: " << *errorStr << " at position: " << *errorPos << std::endl;
        }
        return result;
    }

    __declspec(dllexport) BOOL HelperEvalFilter(const char* filter, const VOID* packet, UINT packetLen, const WINDIVERT_ADDRESS* address) {
        return divertInstance.HelperEvalFilter(filter, packet, packetLen, address);
    }

    __declspec(dllexport) BOOL HelperFormatFilter(const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen) {
        return divertInstance.HelperFormatFilter(filter, layer, buffer, bufLen);
    }

    __declspec(dllexport) UINT16 HelperNtohs(UINT16 x) {
        return divertInstance.HelperNtohs(x);
    }

    __declspec(dllexport) UINT16 HelperHtons(UINT16 x) {
        return divertInstance.HelperHtons(x);
    }

    __declspec(dllexport) UINT32 HelperNtohl(UINT32 x) {
        return divertInstance.HelperNtohl(x);
    }

    __declspec(dllexport) UINT32 HelperHtonl(UINT32 x) {
        return divertInstance.HelperHtonl(x);
    }

    __declspec(dllexport) UINT64 HelperNtohll(UINT64 x) {
        return divertInstance.HelperNtohll(x);
    }

    __declspec(dllexport) UINT64 HelperHtonll(UINT64 x) {
        return divertInstance.HelperHtonll(x);
    }

    __declspec(dllexport) void HelperNtohIPv6Address(const UINT* inAddr, UINT* outAddr) {
        divertInstance.HelperNtohIPv6Address(inAddr, outAddr);
    }

    __declspec(dllexport) void HelperHtonIPv6Address(const UINT* inAddr, UINT* outAddr) {
        divertInstance.HelperHtonIPv6Address(inAddr, outAddr);
    }
}
