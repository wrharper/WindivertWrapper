#include "pch.h"

void CaptureSocketLayerTraffic(const std::vector<DWORD>& targetPids, const PROCESS_INFORMATION& pi);
void CaptureNetworkLayerTraffic(const PROCESS_INFORMATION& pi);
void RunFlowLayerTest();