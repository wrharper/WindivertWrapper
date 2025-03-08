#include "pch.h"
#include "WindivertWrapper.h"
#include "WindivertWrapperExtern.h"
#include <iostream>
#include <stdexcept>
#include <Windows.h>
#include <string> // Include the string header for std::to_string

extern WindivertWrapper g_windivertWrapper; // Extern instance

void TestWinDivertOpenAndCloseEx() {
    std::cout << "Using extern WindivertWrapper instance for TestWinDivertOpenAndClose" << std::endl;
    const char* filter = "true";
    WINDIVERT_LAYER layer = WINDIVERT_LAYER_NETWORK;
    INT16 priority = 0;
    UINT64 flags = 0;

    HANDLE handle = g_windivertWrapper.Open(filter, layer, priority, flags);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open WinDivert handle" << std::endl;
        return;
    }

    std::cout << "Open: Success" << std::endl;

    g_windivertWrapper.Close();

    std::cout << "Close: Success" << std::endl;
}

void TestWinDivertRecvEx() {
    std::cout << "Using extern WindivertWrapper instance for TestWinDivertRecv" << std::endl;
    const char* filter = "true";
    WINDIVERT_LAYER layer = WINDIVERT_LAYER_NETWORK;
    INT16 priority = 0;
    UINT64 flags = 0;

    HANDLE handle = g_windivertWrapper.Open(filter, layer, priority, flags);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open WinDivert handle" << std::endl;
        return;
    }

    std::cout << "Open: Success" << std::endl;

    if (!g_windivertWrapper.SetParam(WINDIVERT_PARAM_QUEUE_LEN, 8192)) {
        std::cerr << "Failed to set queue length" << std::endl;
    }
    if (!g_windivertWrapper.SetParam(WINDIVERT_PARAM_QUEUE_TIME, 2048)) {
        std::cerr << "Failed to set queue time" << std::endl;
    }

    WINDIVERT_ADDRESS address;
    // Allocate packet buffer on the heap
    std::unique_ptr<char[]> packet(new char[65535]);
    UINT recvLen = 0;

    BOOL result = g_windivertWrapper.Recv(&address, packet.get(), 65535, &recvLen);
    if (result) {
        std::cout << "Packet received. Length: " << recvLen << std::endl;
    }
    else {
        DWORD error = GetLastError();
        std::cerr << "Failed to receive packet. Error: " << error << std::endl;
    }

    std::cout << "Press Enter to exit...";
    std::cin.get();
    g_windivertWrapper.Close();
}

void TestWinDivertSendEx() {
    std::cout << "Using extern WindivertWrapper instance for TestWinDivertSend" << std::endl;
    const char* filter = "true";
    WINDIVERT_LAYER layer = WINDIVERT_LAYER_NETWORK;
    INT16 priority = 0;
    UINT64 flags = 0;

    HANDLE handle = g_windivertWrapper.Open(filter, layer, priority, flags);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open WinDivert handle" << std::endl;
        return;
    }

    std::cout << "Open: Success" << std::endl;

    WINDIVERT_ADDRESS address;
    // Create a minimal valid packet (example: a simple IP header)
    std::unique_ptr<char[]> sendPacket(new char[20]);
    memset(sendPacket.get(), 0, 20); // Clear the buffer

    // Set up a basic IP header (minimal example)
    sendPacket[0] = 0x45; // Version and header length
    sendPacket[2] = 0x00; sendPacket[3] = 20; // Total length
    sendPacket[8] = 0x40; // TTL
    sendPacket[9] = 0x06; // Protocol (TCP)

    UINT packetLen = 20; // Explicitly set the packet length
    UINT sendLen = 0;

    BOOL result = g_windivertWrapper.Send(&address, sendPacket.get(), packetLen, &sendLen);
    if (result) {
        std::cout << "Packet sent. Length: " << sendLen << std::endl;
    }
    else {
        DWORD error = GetLastError();
        std::cerr << "Failed to send packet. Error: " << error << std::endl;

        wchar_t* errorMsg = nullptr;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, error, 0, (LPWSTR)&errorMsg, 0, nullptr);
        if (errorMsg) {
            std::wcerr << L"Error message: " << errorMsg << std::endl;
            LocalFree(errorMsg);
        }
    }

    std::cout << "Press Enter to exit...";
    std::cin.get();
    g_windivertWrapper.Close();
}

void TestHelperCalcChecksumsEx(WindivertWrapper& wrapper) {
    std::unique_ptr<char[]> packet(new char[20]);
    memset(packet.get(), 0, 20);

    // Create a minimal valid IP packet (example: a simple IP header)
    packet[0] = 0x45; // Version and header length
    packet[2] = 0x00; packet[3] = 20; // Total length
    packet[8] = 0x40; // TTL
    packet[9] = 0x06; // Protocol (TCP)

    WINDIVERT_ADDRESS addr;
    if (wrapper.HelperCalcChecksums(packet.get(), 20, &addr, 0)) {
        std::cout << "Checksums calculated successfully" << std::endl;
    }
    else {
        std::cerr << "Failed to calculate checksums" << std::endl;
    }
}
void TestHelperDecrementTTLEx(WindivertWrapper& wrapper) {
    std::unique_ptr<char[]> packet(new char[20]);
    memset(packet.get(), 0, 20);

    // Set up a basic IP header with TTL
    packet[0] = 0x45; // Version and header length
    packet[2] = 0x00; packet[3] = 20; // Total length
    packet[8] = 0x40; // Initial TTL
    packet[9] = 0x06; // Protocol (TCP)

    if (wrapper.HelperDecrementTTL(packet.get(), 20)) {
        std::cout << "TTL decremented successfully. New TTL: " << (int)packet[8] << std::endl;
    }
    else {
        std::cerr << "Failed to decrement TTL" << std::endl;
    }
}

void TestHelperEvalFilterEx(WindivertWrapper& wrapper) {
    // Use the same packet from TestHelperCalcChecksums or create a new one
    std::unique_ptr<char[]> packet(new char[20]);
    memset(packet.get(), 0, 20);

    // Create a minimal valid IP packet (example: a simple IP header)
    packet[0] = 0x45; // Version and header length
    packet[2] = 0x00; packet[3] = 20; // Total length
    packet[8] = 0x40; // TTL
    packet[9] = 0x06; // Protocol (TCP)

    // Set source and destination addresses
    // Source address (set it to something plausible)
    packet[12] = 10; packet[13] = 0; packet[14] = 0; packet[15] = 1; // 10.0.0.1

    // Destination address (192.168.1.1)
    packet[16] = 192;
    packet[17] = 168;
    packet[18] = 1;
    packet[19] = 1;

    WINDIVERT_ADDRESS addr;
    memset(&addr, 0, sizeof(addr)); // Ensure the address structure is initialized

    std::cout << "Evaluating filter with packet data:" << std::endl;
    for (int i = 0; i < 20; ++i) {
        std::cout << std::hex << (int)packet[i] << " ";
    }
    std::cout << std::endl;

    // Use a filter string that includes the "outbound" keyword
    if (wrapper.HelperEvalFilter("outbound and ip.DstAddr == 192.168.1.1", packet.get(), 20, &addr)) {
        std::cout << "Filter evaluated successfully" << std::endl;
    }
    else {
        DWORD error = GetLastError();
        std::cerr << "Failed to evaluate filter. Error: " << error << std::endl;

        wchar_t* errorMsg = nullptr;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, error, 0, (LPWSTR)&errorMsg, 0, nullptr);
        if (errorMsg) {
            std::wcerr << L"Error message: " << errorMsg << std::endl;
            LocalFree(errorMsg);
        }
    }
}

void TestHelperEvalFilter2Ex(WindivertWrapper& wrapper) {
    // Use the same packet from TestHelperCalcChecksums or create a new one
    std::unique_ptr<char[]> packet(new char[20]);
    memset(packet.get(), 0, 20);

    // Create a minimal valid IP packet (example: a simple IP header)
    packet[0] = 0x45; // Version and header length
    packet[2] = 0x00; packet[3] = 20; // Total length
    packet[8] = 0x40; // TTL
    packet[9] = 0x06; // Protocol (TCP)

    // Set source and destination addresses
    // Source address (set it to something plausible)
    packet[12] = 10; packet[13] = 0; packet[14] = 0; packet[15] = 1; // 10.0.0.1

    // Destination address (192.168.1.1)
    packet[16] = 192;
    packet[17] = 168;
    packet[18] = 1;
    packet[19] = 1;

    // Initialize WINDIVERT_ADDRESS structure and set outbound flag
    WINDIVERT_ADDRESS addr;
    memset(&addr, 0, sizeof(addr)); // Ensure the address structure is initialized
    addr.Outbound = 1; // Explicitly set outbound direction

    std::cout << "Evaluating filter with packet data:" << std::endl;
    for (int i = 0; i < 20; ++i) {
        std::cout << std::hex << (int)packet[i] << " ";
    }
    std::cout << std::endl;

    // Use a filter string that includes the "outbound" keyword
    if (wrapper.HelperEvalFilter("outbound and ip.DstAddr == 192.168.1.1", packet.get(), 20, &addr)) {
        std::cout << "Filter evaluated successfully" << std::endl;
    }
    else {
        DWORD error = GetLastError();
        std::cerr << "Failed to evaluate filter. Error: " << error << std::endl;

        wchar_t* errorMsg = nullptr;
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, error, 0, (LPWSTR)&errorMsg, 0, nullptr);
        if (errorMsg) {
            std::wcerr << L"Error message: " << errorMsg << std::endl;
            LocalFree(errorMsg);
        }
    }
}

bool TestCompileFilterEx(WindivertWrapper& wrapper) {
    char compiledFilter[1024];
    const char* errorStr = nullptr;
    UINT errorPos = 0;

    if (wrapper.HelperCompileFilter("outbound and ip.DstAddr == 192.168.1.1", WINDIVERT_LAYER_NETWORK, compiledFilter, sizeof(compiledFilter), &errorStr, &errorPos)) {
        std::cout << "Filter compiled successfully" << std::endl;
        return true;
    }
    else {
        std::cerr << "Failed to compile filter. Error: " << (errorStr ? errorStr : "unknown") << " at position: " << errorPos << std::endl;
        return false;
    }
}

void TestHelperFunctionsEx() {
    std::cout << "Using extern WindivertWrapper instance for TestHelperFunctions" << std::endl;

    // Test HelperHashPacket
    const char* testPacket = "TestPacketData";
    UINT64 hash = g_windivertWrapper.HelperHashPacket(testPacket, static_cast<UINT>(strlen(testPacket)));
    std::cout << "Hash of test packet: " << hash << std::endl;

    // Test HelperParseIPv4Address
    const char* ipv4AddrStr = "192.168.1.1";
    UINT32 ipv4Addr;
    if (g_windivertWrapper.HelperParseIPv4Address(ipv4AddrStr, &ipv4Addr)) {
        std::cout << "Parsed IPv4 address: " << ipv4Addr << std::endl;
    }
    else {
        std::cerr << "Failed to parse IPv4 address" << std::endl;
    }

    // Test HelperFormatIPv4Address
    char ipv4AddrBuffer[16];
    if (g_windivertWrapper.HelperFormatIPv4Address(ipv4Addr, ipv4AddrBuffer, sizeof(ipv4AddrBuffer))) {
        std::cout << "Formatted IPv4 address: " << ipv4AddrBuffer << std::endl;
    }
    else {
        std::cerr << "Failed to format IPv4 address" << std::endl;
    }

    // Test HelperParseIPv6Address
    const char* ipv6AddrStr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";
    UINT32 ipv6Addr[4];
    if (g_windivertWrapper.HelperParseIPv6Address(ipv6AddrStr, ipv6Addr)) {
        std::cout << "Parsed IPv6 address: ";
        for (int i = 0; i < 4; ++i) {
            std::cout << ipv6Addr[i] << (i < 3 ? ":" : "\n");
        }
    }
    else {
        std::cerr << "Failed to parse IPv6 address" << std::endl;
    }

    // Test HelperFormatIPv6Address
    char ipv6AddrBuffer[40];
    if (g_windivertWrapper.HelperFormatIPv6Address(ipv6Addr, ipv6AddrBuffer, sizeof(ipv6AddrBuffer))) {
        std::cout << "Formatted IPv6 address: " << ipv6AddrBuffer << std::endl;
    }
    else {
        std::cerr << "Failed to format IPv6 address" << std::endl;
    }

    // Test HelperCalcChecksums
    TestHelperCalcChecksumsEx(g_windivertWrapper);

    // Test HelperDecrementTTL
    TestHelperDecrementTTLEx(g_windivertWrapper);

    // Test HelperEvalFilter
    if (TestCompileFilterEx(g_windivertWrapper)) {
        //TestHelperEvalFilter(g_windivertWrapper);
        TestHelperEvalFilter2Ex(g_windivertWrapper);
    }

    std::cout << "Press Enter to exit...";
    std::cin.get();
    g_windivertWrapper.Close();
}

void TestBlockSpecificIPEx() {
    const char* filter = "ip.SrcAddr == 192.168.1.1";
    WINDIVERT_LAYER layer = WINDIVERT_LAYER_NETWORK;
    INT16 priority = 0;
    UINT64 flags = 0;

    HANDLE handle = g_windivertWrapper.Open(filter, layer, priority, flags);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "Failed to open WinDivert handle for IP blocking" << std::endl;
        return;
    }

    std::cout << "IP blocking handle opened successfully" << std::endl;

    WINDIVERT_ADDRESS address;
    std::unique_ptr<char[]> packet(new char[65535]);
    UINT recvLen = 0;

    // Ensure continuous blocking
    while (true) {
        BOOL result = g_windivertWrapper.Recv(&address, packet.get(), 65535, &recvLen);
        if (result) {
            // Immediately drop the packet without forwarding
            std::cout << "Blocked packet received. Length: " << recvLen << std::endl;
        }
        else {
            DWORD error = GetLastError();
            if (error != ERROR_NO_MORE_ITEMS) {
                std::cerr << "Failed to receive packet for IP blocking. Error: " << error << std::endl;
            }
        }
    }

    g_windivertWrapper.Close();
    std::cout << "IP blocking handle closed successfully" << std::endl;
}

int StartExternTesting() {
    HMODULE hWinDivert = LoadLibrary(TEXT("WinDivert.dll"));
    if (!hWinDivert) {
        DWORD error = GetLastError();
        std::cerr << "Failed to load WinDivert.dll. Error: " << std::to_string(error) << std::endl;
        return 1;
    }

    std::cout << "WinDivert.dll loaded successfully at startup" << std::endl;

    try {
        //TestWinDivertOpenAndCloseEx();
        //TestWinDivertRecvEx();
        //TestWinDivertSendEx();
        //TestHelperFunctionsEx();
        TestBlockSpecificIPEx();
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in test functions: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception occurred in test functions." << std::endl;
    }

    FreeLibrary(hWinDivert);

    return 0;
}