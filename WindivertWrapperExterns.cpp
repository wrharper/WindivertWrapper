#include "WindivertWrapper.h"
#include <stdexcept>
#include <iostream> // For debug output

// Create an instance of WindivertWrapper
static WindivertWrapper wrapper;

extern "C" __declspec(dllexport) HANDLE WINAPI WindivertOpen(
    const char* filter,
    WINDIVERT_LAYER layer,
    INT16 priority,
    UINT64 flags
) {
    std::cout << "WindivertOpen called with filter: " << filter << std::endl;
    try {
        return wrapper.Open(filter, layer, priority, flags);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertOpen: " << ex.what() << std::endl;
        return INVALID_HANDLE_VALUE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertOpen" << std::endl;
        return INVALID_HANDLE_VALUE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertClose(HANDLE handle) {
    std::cout << "WindivertClose called" << std::endl;
    try {
        return wrapper.Close();
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertClose: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertClose" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertRecv(
    HANDLE handle,
    PVOID packet,
    UINT packetLen,
    UINT* recvLen,
    WINDIVERT_ADDRESS* address
) {
    //std::cout << "WindivertRecv called" << std::endl;
    try {
        return wrapper.Recv(address, packet, packetLen, recvLen);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertRecv: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertRecv" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertRecvEx(
    HANDLE handle,
    PVOID packet,
    UINT packetLen,
    UINT* recvLen,
    UINT64 flags,
    WINDIVERT_ADDRESS* address,
    UINT* addrLen,
    LPOVERLAPPED lpOverlapped
) {
    //std::cout << "WindivertRecvEx called" << std::endl;
    try {
        return wrapper.RecvEx(address, packet, packetLen, recvLen, flags, addrLen, lpOverlapped);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertRecvEx: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertRecvEx" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertSend(
    HANDLE handle,
    const VOID* packet,
    UINT packetLen,
    UINT* sendLen,
    const WINDIVERT_ADDRESS* address
) {
    std::cout << "WindivertSend called" << std::endl;
    try {
        return wrapper.Send(address, packet, packetLen, sendLen);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertSend: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertSend" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertSendEx(
    HANDLE handle,
    const VOID* packet,
    UINT packetLen,
    UINT* sendLen,
    UINT64 flags,
    const WINDIVERT_ADDRESS* address,
    UINT addrLen,
    LPOVERLAPPED lpOverlapped
) {
    std::cout << "WindivertSendEx called" << std::endl;
    try {
        return wrapper.SendEx(address, packet, packetLen, sendLen, flags, addrLen, lpOverlapped);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertSendEx: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertSendEx" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertShutdown(
    HANDLE handle,
    WINDIVERT_SHUTDOWN how
) {
    std::cout << "WindivertShutdown called" << std::endl;
    try {
        return wrapper.Shutdown(how);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertShutdown: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertShutdown" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertSetParam(
    HANDLE handle,
    WINDIVERT_PARAM param,
    UINT64 value
) {
    std::cout << "WindivertSetParam called" << std::endl;
    try {
        return wrapper.SetParam(param, value);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertSetParam: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertSetParam" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertGetParam(
    HANDLE handle,
    WINDIVERT_PARAM param,
    UINT64* value
) {
    std::cout << "WindivertGetParam called" << std::endl;
    try {
        return wrapper.GetParam(param, value);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertGetParam: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertGetParam" << std::endl;
        return FALSE;
    }
}

// Helper functions

extern "C" __declspec(dllexport) UINT64 WINAPI WindivertHelperHashPacket(
    const VOID* pPacket,
    UINT packetLen,
    UINT64 seed
) {
    std::cout << "WindivertHelperHashPacket called" << std::endl;
    try {
        return wrapper.HelperHashPacket(pPacket, packetLen, seed);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperHashPacket: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperHashPacket" << std::endl;
        return 0;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperParsePacket(
    const VOID* pPacket,
    UINT packetLen,
    WINDIVERT_IPHDR** ppIpHdr,
    WINDIVERT_IPV6HDR** ppIpv6Hdr,
    UINT8* pProtocol,
    WINDIVERT_ICMPHDR** ppIcmpHdr,
    WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr,
    WINDIVERT_TCPHDR** ppTcpHdr,
    WINDIVERT_UDPHDR** ppUdpHdr,
    PVOID** ppData,
    UINT* pDataLen
) {
    std::cout << "WindivertHelperParsePacket called" << std::endl;
    try {
        return wrapper.HelperParsePacket(pPacket, packetLen, ppIpHdr, ppIpv6Hdr, pProtocol, ppIcmpHdr, ppIcmpv6Hdr, ppTcpHdr, ppUdpHdr, ppData, pDataLen);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperParsePacket: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperParsePacket" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperParseIPv4Address(
    const char* addrStr,
    UINT32* pAddr
) {
    std::cout << "WindivertHelperParseIPv4Address called" << std::endl;
    try {
        return wrapper.HelperParseIPv4Address(addrStr, pAddr);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperParseIPv4Address: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperParseIPv4Address" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperParseIPv6Address(
    const char* addrStr,
    UINT32* pAddr
) {
    std::cout << "WindivertHelperParseIPv6Address called" << std::endl;
    try {
        return wrapper.HelperParseIPv6Address(addrStr, pAddr);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperParseIPv6Address: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperParseIPv6Address" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperFormatIPv4Address(
    UINT32 addr,
    char* buffer,
    UINT bufLen
) {
    std::cout << "WindivertHelperFormatIPv4Address called" << std::endl;
    try {
        return wrapper.HelperFormatIPv4Address(addr, buffer, bufLen);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperFormatIPv4Address: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperFormatIPv4Address" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperFormatIPv6Address(
    const UINT32* pAddr,
    char* buffer,
    UINT bufLen
) {
    std::cout << "WindivertHelperFormatIPv6Address called" << std::endl;
    try {
        return wrapper.HelperFormatIPv6Address(pAddr, buffer, bufLen);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperFormatIPv6Address: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperFormatIPv6Address" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperCalcChecksums(
    VOID* pPacket,
    UINT packetLen,
    WINDIVERT_ADDRESS* pAddr,
    UINT64 flags
) {
    std::cout << "WindivertHelperCalcChecksums called" << std::endl;
    try {
        return wrapper.HelperCalcChecksums(pPacket, packetLen, pAddr, flags);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperCalcChecksums: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperCalcChecksums" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperDecrementTTL(
    VOID* pPacket,
    UINT packetLen
) {
    std::cout << "WindivertHelperDecrementTTL called" << std::endl;
    try {
        return wrapper.HelperDecrementTTL(pPacket, packetLen);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperDecrementTTL: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperDecrementTTL" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperCompileFilter(
    const char* filter,
    WINDIVERT_LAYER layer,
    char* object,
    UINT objLen,
    const char** errorStr,
    UINT* errorPos
) {
    std::cout << "WindivertHelperCompileFilter called" << std::endl;
    try {
        return wrapper.HelperCompileFilter(filter, layer, object, objLen, errorStr, errorPos);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperCompileFilter: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperCompileFilter" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperEvalFilter(
    const char* filter,
    const VOID* pPacket,
    UINT packetLen,
    const WINDIVERT_ADDRESS* pAddr
) {
    std::cout << "WindivertHelperEvalFilter called" << std::endl;
    try {
        return wrapper.HelperEvalFilter(filter, pPacket, packetLen, pAddr);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperEvalFilter: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperEvalFilter" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) BOOL WINAPI WindivertHelperFormatFilter(
    const char* filter,
    WINDIVERT_LAYER layer,
    char* buffer,
    UINT bufLen
) {
    std::cout << "WindivertHelperFormatFilter called" << std::endl;
    try {
        return wrapper.HelperFormatFilter(filter, layer, buffer, bufLen);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperFormatFilter: " << ex.what() << std::endl;
        return FALSE;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperFormatFilter" << std::endl;
        return FALSE;
    }
}

extern "C" __declspec(dllexport) UINT16 WINAPI WindivertHelperNtohs(UINT16 x) {
    std::cout << "WindivertHelperNtohs called" << std::endl;
    try {
        return wrapper.HelperNtohs(x);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperNtohs: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperNtohs" << std::endl;
        return 0;
    }
}

extern "C" __declspec(dllexport) UINT16 WINAPI WindivertHelperHtons(UINT16 x) {
    std::cout << "WindivertHelperHtons called" << std::endl;
    try {
        return wrapper.HelperHtons(x);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperHtons: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperHtons" << std::endl;
        return 0;
    }
}

extern "C" __declspec(dllexport) UINT32 WINAPI WindivertHelperNtohl(UINT32 x) {
    std::cout << "WindivertHelperNtohl called" << std::endl;
    try {
        return wrapper.HelperNtohl(x);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperNtohl: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperNtohl" << std::endl;
        return 0;
    }
}

extern "C" __declspec(dllexport) UINT32 WINAPI WindivertHelperHtonl(UINT32 x) {
    std::cout << "WindivertHelperHtonl called" << std::endl;
    try {
        return wrapper.HelperHtonl(x);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperHtonl: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperHtonl" << std::endl;
        return 0;
    }
}

extern "C" __declspec(dllexport) UINT64 WINAPI WindivertHelperNtohll(UINT64 x) {
    std::cout << "WindivertHelperNtohll called" << std::endl;
    try {
        return wrapper.HelperNtohll(x);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperNtohll: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperNtohll" << std::endl;
        return 0;
    }
}

extern "C" __declspec(dllexport) UINT64 WINAPI WindivertHelperHtonll(UINT64 x) {
    std::cout << "WindivertHelperHtonll called" << std::endl;
    try {
        return wrapper.HelperHtonll(x);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperHtonll: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperHtonll" << std::endl;
        return 0;
    }
}

extern "C" __declspec(dllexport) void WINAPI WindivertHelperNtohIPv6Address(
    const UINT* inAddr,
    UINT* outAddr
) {
    std::cout << "WindivertHelperNtohIPv6Address called" << std::endl;
    try {
        wrapper.HelperNtohIPv6Address(inAddr, outAddr);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperNtohIPv6Address: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperNtohIPv6Address" << std::endl;
    }
}

extern "C" __declspec(dllexport) void WINAPI WindivertHelperHtonIPv6Address(
    const UINT* inAddr,
    UINT* outAddr
) {
    std::cout << "WindivertHelperHtonIPv6Address called" << std::endl;
    try {
        wrapper.HelperHtonIPv6Address(inAddr, outAddr);
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in WindivertHelperHtonIPv6Address: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception in WindivertHelperHtonIPv6Address" << std::endl;
    }
}
