#pragma once

#ifdef WINDIVERTWRAPPER_EXPORTS
#define WINDIVERTWRAPPER_API __declspec(dllexport)
#else
#define WINDIVERTWRAPPER_API __declspec(dllimport)
#endif

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winsock2.h>
#include "windivert.h"
#include <cstdint>  // For standard integer types like uint32_t

// Ensure the structure is packed without padding
#pragma pack(push, 1)
struct IPV4_HEADER {
    uint8_t version_ihl;           // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t type_of_service;       // Type of Service
    uint16_t total_length;         // Total Length
    uint16_t identification;       // Identification
    uint16_t flags_fragment;       // Flags (3 bits) + Fragment Offset (13 bits)
    uint8_t ttl;                   // Time to Live
    uint8_t protocol;              // Protocol
    uint16_t header_checksum;      // Header Checksum
    uint32_t src_addr;             // Source Address
    uint32_t dest_addr;            // Destination Address
};
#pragma pack(pop)

// Declare the external instance of IPV4_HEADER
extern IPV4_HEADER globalIpv4Header;

// Define the function pointer typedefs for WinDivert functions
typedef HANDLE(WINAPI* WinDivertOpen_t)(const char*, WINDIVERT_LAYER, INT16, UINT64);
typedef BOOL(WINAPI* WinDivertClose_t)(HANDLE);
typedef BOOL(WINAPI* WinDivertRecv_t)(HANDLE, PVOID, UINT, UINT*, WINDIVERT_ADDRESS*);
typedef BOOL(WINAPI* WinDivertRecvEx_t)(HANDLE, PVOID, UINT, UINT*, UINT64, WINDIVERT_ADDRESS*, UINT*, LPOVERLAPPED);
typedef BOOL(WINAPI* WinDivertSend_t)(HANDLE, const VOID*, UINT, UINT*, const WINDIVERT_ADDRESS*);
typedef BOOL(WINAPI* WinDivertSendEx_t)(HANDLE, const VOID*, UINT, UINT*, UINT64, const WINDIVERT_ADDRESS*, UINT, LPOVERLAPPED);
typedef BOOL(WINAPI* WinDivertShutdown_t)(HANDLE, WINDIVERT_SHUTDOWN);
typedef BOOL(WINAPI* WinDivertSetParam_t)(HANDLE, WINDIVERT_PARAM, UINT64);
typedef BOOL(WINAPI* WinDivertGetParam_t)(HANDLE, WINDIVERT_PARAM, UINT64*);

// Define the function pointer typedefs for WinDivert helper functions
typedef UINT64(WINAPI* WinDivertHelperHashPacket_t)(const VOID*, UINT, UINT64);
typedef BOOL(WINAPI* WinDivertHelperParsePacket_t)(const VOID*, UINT, WINDIVERT_IPHDR**, WINDIVERT_IPV6HDR**, UINT8*, WINDIVERT_ICMPHDR**,
    WINDIVERT_ICMPV6HDR**, WINDIVERT_TCPHDR**, WINDIVERT_UDPHDR**, PVOID**, UINT*);
typedef BOOL(WINAPI* WinDivertHelperParseIPv4Address_t)(const char*, UINT32*);
typedef BOOL(WINAPI* WinDivertHelperParseIPv6Address_t)(const char*, UINT32*);
typedef BOOL(WINAPI* WinDivertHelperFormatIPv4Address_t)(UINT32, char*, UINT);
typedef BOOL(WINAPI* WinDivertHelperFormatIPv6Address_t)(const UINT32*, char*, UINT);
typedef BOOL(WINAPI* WinDivertHelperCalcChecksums_t)(VOID*, UINT, WINDIVERT_ADDRESS*, UINT64);
typedef BOOL(WINAPI* WinDivertHelperDecrementTTL_t)(VOID*, UINT);
typedef BOOL(WINAPI* WinDivertHelperCompileFilter_t)(const char*, WINDIVERT_LAYER, char*, UINT, const char**, UINT*);
typedef BOOL(WINAPI* WinDivertHelperEvalFilter_t)(const char*, const VOID*, UINT, const WINDIVERT_ADDRESS*);
typedef BOOL(WINAPI* WinDivertHelperFormatFilter_t)(const char*, WINDIVERT_LAYER, char*, UINT);

typedef UINT16(WINAPI* WinDivertHelperNtohs_t)(UINT16);
typedef UINT16(WINAPI* WinDivertHelperHtons_t)(UINT16);
typedef UINT32(WINAPI* WinDivertHelperNtohl_t)(UINT32);
typedef UINT32(WINAPI* WinDivertHelperHtonl_t)(UINT32);
typedef UINT64(WINAPI* WinDivertHelperNtohll_t)(UINT64);
typedef UINT64(WINAPI* WinDivertHelperHtonll_t)(UINT64);
typedef void(WINAPI* WinDivertHelperNtohIPv6Address_t)(const UINT*, UINT*);
typedef void(WINAPI* WinDivertHelperHtonIPv6Address_t)(const UINT*, UINT*);

class WINDIVERTWRAPPER_API WindivertWrapper {
public:
    WindivertWrapper();
    ~WindivertWrapper();

    // Public methods
    HANDLE Open(const char* filter, WINDIVERT_LAYER layer, INT16 priority, UINT64 flags);
    BOOL Close();
    BOOL Recv(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen) const;
    BOOL RecvEx(WINDIVERT_ADDRESS* address, PVOID packet, UINT packetLen, UINT* recvLen, UINT64 flags, UINT* addrLen, LPOVERLAPPED lpOverlapped) const;
    BOOL Send(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen) const;
    BOOL SendEx(const WINDIVERT_ADDRESS* address, const VOID* packet, UINT packetLen, UINT* sendLen, UINT64 flags, UINT addrLen, LPOVERLAPPED lpOverlapped) const;
    BOOL Shutdown(WINDIVERT_SHUTDOWN how) const;
    BOOL SetParam(WINDIVERT_PARAM param, UINT64 value) const;
    BOOL GetParam(WINDIVERT_PARAM param, UINT64* value) const;

    // Helper functions
    UINT64 HelperHashPacket(const VOID* pPacket, UINT packetLen, UINT64 seed = 0) const;
    BOOL HelperParsePacket(const VOID* pPacket, UINT packetLen, WINDIVERT_IPHDR** ppIpHdr, WINDIVERT_IPV6HDR** ppIpv6Hdr, UINT8* pProtocol,
        WINDIVERT_ICMPHDR** ppIcmpHdr, WINDIVERT_ICMPV6HDR** ppIcmpv6Hdr, WINDIVERT_TCPHDR** ppTcpHdr, WINDIVERT_UDPHDR** ppUdpHdr, PVOID** ppData,
        UINT* pDataLen) const;
    BOOL HelperParseIPv4Address(const char* addrStr, UINT32* pAddr) const;
    BOOL HelperParseIPv6Address(const char* addrStr, UINT32* pAddr) const;
    BOOL HelperFormatIPv4Address(UINT32 addr, char* buffer, UINT bufLen) const;
    BOOL HelperFormatIPv6Address(const UINT32* pAddr, char* buffer, UINT bufLen) const;
    BOOL HelperCalcChecksums(VOID* pPacket, UINT packetLen, WINDIVERT_ADDRESS* pAddr, UINT64 flags) const;
    BOOL HelperDecrementTTL(VOID* pPacket, UINT packetLen) const;
    BOOL HelperCompileFilter(const char* filter, WINDIVERT_LAYER layer, char* object, UINT objLen, const char** errorStr, UINT* errorPos) const;
    BOOL HelperEvalFilter(const char* filter, const VOID* pPacket, UINT packetLen, const WINDIVERT_ADDRESS* pAddr) const;
    BOOL HelperFormatFilter(const char* filter, WINDIVERT_LAYER layer, char* buffer, UINT bufLen) const;

    UINT16 HelperNtohs(UINT16 x) const;
    UINT16 HelperHtons(UINT16 x) const;
    UINT32 HelperNtohl(UINT32 x) const;
    UINT32 HelperHtonl(UINT32 x) const;
    UINT64 HelperNtohll(UINT64 x) const;
    UINT64 HelperHtonll(UINT64 x) const;
    void HelperNtohIPv6Address(const UINT* inAddr, UINT* outAddr) const;
    void HelperHtonIPv6Address(const UINT* inAddr, UINT* outAddr) const;

private:
    void LoadWinDivertFunctions();

    HANDLE handle;
    HMODULE hWinDivert;

    // Function pointers for WinDivert functions
    WinDivertOpen_t WinDivertOpen;
    WinDivertClose_t WinDivertClose;
    WinDivertRecv_t WinDivertRecv;
    WinDivertRecvEx_t WinDivertRecvEx;
    WinDivertSend_t WinDivertSend;
    WinDivertSendEx_t WinDivertSendEx;
    WinDivertShutdown_t WinDivertShutdown;
    WinDivertSetParam_t WinDivertSetParam;
    WinDivertGetParam_t WinDivertGetParam;

    // Function pointers for WinDivert helper functions
    WinDivertHelperHashPacket_t WinDivertHelperHashPacket;
    WinDivertHelperParsePacket_t WinDivertHelperParsePacket;
    WinDivertHelperParseIPv4Address_t WinDivertHelperParseIPv4Address;
    WinDivertHelperParseIPv6Address_t WinDivertHelperParseIPv6Address;
    WinDivertHelperFormatIPv4Address_t WinDivertHelperFormatIPv4Address;
    WinDivertHelperFormatIPv6Address_t WinDivertHelperFormatIPv6Address;
    WinDivertHelperCalcChecksums_t WinDivertHelperCalcChecksums;
    WinDivertHelperDecrementTTL_t WinDivertHelperDecrementTTL;
    WinDivertHelperCompileFilter_t WinDivertHelperCompileFilter;
    WinDivertHelperEvalFilter_t WinDivertHelperEvalFilter;
    WinDivertHelperFormatFilter_t WinDivertHelperFormatFilter;
    WinDivertHelperNtohs_t WinDivertHelperNtohs;
    WinDivertHelperHtons_t WinDivertHelperHtons;
    WinDivertHelperNtohl_t WinDivertHelperNtohl;
    WinDivertHelperHtonl_t WinDivertHelperHtonl;
    WinDivertHelperNtohll_t WinDivertHelperNtohll;
    WinDivertHelperHtonll_t WinDivertHelperHtonll;
    WinDivertHelperNtohIPv6Address_t WinDivertHelperNtohIPv6Address;
    WinDivertHelperHtonIPv6Address_t WinDivertHelperHtonIPv6Address;
};