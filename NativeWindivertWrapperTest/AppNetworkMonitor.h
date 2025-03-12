#include "pch.h"

void ProcessPacketInfo(const std::vector<DWORD>& targetPids, const WINDIVERT_ADDRESS& addr, const char* packetData, UINT packetLen);
void CaptureSocketLayerTraffic(const std::vector<DWORD>& targetPids, const PROCESS_INFORMATION& pi);
void CaptureNetworkLayerTraffic(const PROCESS_INFORMATION& pi);
void RunFlowLayerTest();