#include "pch.h"
#include "TrafficMonitor.h"

std::atomic<bool> keepMonitoringFlowNetwork;

void CaptureSocketLayerTraffic(const std::vector<DWORD>& targetPids, const PROCESS_INFORMATION& pi) {
    std::cout << "Target PIDs being used in Capture Hook: ";
    for (const auto& pid : targetPids) {
        std::cout << pid << " ";
    }
    std::cout << std::endl;

    WindivertWrapper divertInstance;

    // Construct filter for all target PIDs
    std::string filter = ConstructPidFilter(targetPids);
    std::cout << "Opening WinDivert handle with filter: " << filter << std::endl;

    HANDLE handle = divertInstance.Open(filter.c_str(), WINDIVERT_LAYER_SOCKET, 0, WINDIVERT_FLAG_RECV_ONLY);

    if (handle == INVALID_HANDLE_VALUE) {
        DWORD errorCode = GetLastError();
        std::cerr << "Failed to open WinDivert handle. Error code: " << errorCode << std::endl;
        return;
    }

    while (keepMonitoringFlowNetwork.load()) {
        WINDIVERT_ADDRESS addr;
        std::unique_ptr<char[]> packet(new char[PACKET_BUF_SIZE]);
        UINT packetLen = 0;

        // Receive the packet
        if (!divertInstance.Recv(&addr, packet.get(), PACKET_BUF_SIZE, &packetLen)) {
            DWORD errorCode = GetLastError();
            std::cerr << "WinDivertRecv failed. Error code: " << errorCode << std::endl;
            continue;
        }

        if (packetLen < sizeof(WINDIVERT_IPHDR)) {
            std::cerr << "Invalid packet length (" << packetLen << " bytes). Dumping raw packet data:" << std::endl;
            std::cout << "Packet Data (Hex): ";
            for (UINT i = 0; i < 128; ++i) {
                printf("%02X ", (unsigned char)packet[i]);
            }
            std::cout << std::endl;
            continue;
        }

        // Parse the IP header
        WINDIVERT_IPHDR* ip_header = (WINDIVERT_IPHDR*)packet.get();
        std::string srcIp = ConvertIPv4ToString(ip_header->SrcAddr);
        std::string dstIp = ConvertIPv4ToString(ip_header->DstAddr);

        // Determine the PID for the packet
        DWORD packetPid = GetProcessIdFromPacket(addr, packet.get(), packetLen);

        // Get the application name from the PID
        std::string appName = GetApplicationNameFromPid(packetPid);

        // Check if packet PID matches one of the target PIDs
        if (packetPid != 0 &&
            std::find(targetPids.begin(), targetPids.end(), packetPid) != targetPids.end() &&
            appName == "chrome.exe") {
            std::cout << "PID: " << packetPid << " Application: " << appName << std::endl;
            std::cout << "IP Header: SrcAddr=" << srcIp << " DstAddr=" << dstIp << std::endl;

            // Check the protocol and display transport-layer details
            if (ip_header->Protocol == IPPROTO_TCP) {
                WINDIVERT_TCPHDR* tcp_header = (WINDIVERT_TCPHDR*)(packet.get() + (ip_header->HdrLength * 4));
                std::cout << "TCP Header: SrcPort=" << ntohs(tcp_header->SrcPort)
                    << " DstPort=" << ntohs(tcp_header->DstPort) << std::endl;
            }
            else if (ip_header->Protocol == IPPROTO_UDP) {
                WINDIVERT_UDPHDR* udp_header = (WINDIVERT_UDPHDR*)(packet.get() + (ip_header->HdrLength * 4));
                std::cout << "UDP Header: SrcPort=" << ntohs(udp_header->SrcPort)
                    << " DstPort=" << ntohs(udp_header->DstPort) << std::endl;
            }

            // Display raw packet data
            std::cout << "Packet Data (Hex): ";
            for (UINT i = 0; i < packetLen; ++i) {
                printf("%02X ", (unsigned char)packet[i]);
            }
            std::cout << std::endl;
        }
    }

    std::cout << "Closing WinDivert handle." << std::endl;
    divertInstance.Close();
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void CaptureNetworkLayerTraffic(const PROCESS_INFORMATION& pi) {
    std::cout << "Monitoring traffic for target application path: " << appPath << std::endl;

    // Dynamically extract the application name from the full path
    std::string targetAppName = ExtractAppNameFromPath(appPath);
    std::cout << "Target Applicati on Name: " << targetAppName << std::endl;

    WindivertWrapper divertInstance;
    std::string filter = "true"; // General filter for capturing all traffic
    std::cout << "Opening WinDivert handle with filter: " << filter << std::endl;

    HANDLE handle = divertInstance.Open(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY);

    if (handle == INVALID_HANDLE_VALUE) {
        DWORD errorCode = GetLastError();
        std::cerr << "Failed to open WinDivert handle. Error code: " << errorCode << std::endl;
        return;
    }

    while (keepMonitoringFlowNetwork.load()) {
        WINDIVERT_ADDRESS addr;
        std::unique_ptr<char[]> packet(new char[PACKET_BUF_SIZE]);
        UINT packetLen = 0;

        // Receive the packet
        if (!divertInstance.Recv(&addr, packet.get(), PACKET_BUF_SIZE, &packetLen)) {
            DWORD errorCode = GetLastError();
            std::cerr << "WinDivertRecv failed. Error code: " << errorCode << std::endl;
            continue;
        }

        // Assign packet.get() to a local variable
        char* packetData = packet.get();

        // Validate packet length
        if (packetLen < sizeof(WINDIVERT_IPHDR)) {
            std::cerr << "Invalid packet length." << std::endl;
            continue;
        }

        // Parse the IP header
        WINDIVERT_IPHDR* ip_header = (WINDIVERT_IPHDR*)packetData;
        std::string srcIp = ConvertIPv4ToString(ip_header->SrcAddr);
        std::string dstIp = ConvertIPv4ToString(ip_header->DstAddr);

        // Determine the PID for the packet
        DWORD packetPid = GetProcessIdFromPacket(addr, packetData, packetLen);

        // Get the application name from the PID
        std::string appName = GetApplicationNameFromPid(packetPid);

        // Block the traffic only if it matches the target application
        if (packetPid != 0 && appName == targetAppName) {
            std::cout << "Blocked traffic for PID: " << packetPid << " Application: " << appName << std::endl;
            std::cout << "IP Header: SrcAddr=" << srcIp << " DstAddr=" << dstIp << std::endl;

            // Check the protocol and display transport-layer details
            if (ip_header->Protocol == IPPROTO_TCP) {
                WINDIVERT_TCPHDR* tcp_header = (WINDIVERT_TCPHDR*)(packetData + (ip_header->HdrLength * 4));
                std::cout << "TCP Header: SrcPort=" << ntohs(tcp_header->SrcPort)
                    << " DstPort=" << ntohs(tcp_header->DstPort) << std::endl;
            }
            else if (ip_header->Protocol == IPPROTO_UDP) {
                WINDIVERT_UDPHDR* udp_header = (WINDIVERT_UDPHDR*)(packetData + (ip_header->HdrLength * 4));
                std::cout << "UDP Header: SrcPort=" << ntohs(udp_header->SrcPort)
                    << " DstPort=" << ntohs(udp_header->DstPort) << std::endl;
            }

            // Do not re-inject the blocked packet
            continue;
        }

        // Re-inject the packet back into the network stack (allow all other traffic)
        //UINT sendLen = 0; // Variable to store the number of bytes sent
        if (!divertInstance.Send(&addr, packetData, packetLen, &packetLen)) {
            DWORD errorCode = GetLastError();
            std::cerr << "WinDivertSend failed. Error code: " << errorCode << std::endl;
        }

    }

    std::cout << "Closing WinDivert handle." << std::endl;
    divertInstance.Close();
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}

void RunFlowLayerTest() {
    // Set up the console control handler for clean termination
    if (!SetConsoleCtrlHandler(ConsoleHandler, TRUE)) {
        std::cerr << "Failed to set control handler. Error code: " << GetLastError() << std::endl;
        return;
    }

    // Launch the target application via a PowerShell script
    std::string scriptPath = "LaunchChrome.ps1"; // Adjust the script path as needed
    LaunchPowerShellScript(scriptPath);

    // Give the application some time to launch and initialize
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Retrieve all PIDs for the target application (chrome.exe)
    std::vector<DWORD> targetPids = GetAllPidsByAppName("chrome.exe");
    if (targetPids.empty()) {
        std::cerr << "Failed to find any process IDs for chrome.exe. Exiting." << std::endl;
        return;
    }

    // Display the PIDs for transparency
    std::cout << "Found the following chrome.exe process IDs: ";
    for (const auto& pid : targetPids) {
        std::cout << pid << " ";
    }
    std::cout << std::endl;

    // Initialize monitoring flags
    keepMonitoringApplication.store(true);
    keepMonitoringFlowNetwork.store(true);

    // Start capturing traffic for the retrieved PIDs
    CaptureSocketLayerTraffic(targetPids, g_processInfo);

    // Monitor termination of all instances of the application (chrome.exe)
    MonitorProcessTermination(TEXT("chrome.exe"));

    // Stop traffic monitoring
    keepMonitoringFlowNetwork.store(false);

    // Terminate the target application if the console is closed
    if (g_processInfo.hProcess != NULL) {
        TerminateProcess(g_processInfo.hProcess, 0);
        CloseHandle(g_processInfo.hProcess);
        g_processInfo.hProcess = NULL;
    }
    g_processInfo.hThread = NULL;

    // Release the console
    FreeConsole();
}
