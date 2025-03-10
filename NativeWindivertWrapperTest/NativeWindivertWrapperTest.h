#pragma once

#include "WindivertWrapper.h"

void TestWinDivertOpenAndClose();
void TestWinDivertRecv();
void TestHelperCalcChecksums(WindivertWrapper& wrapper);
void TestHelperDecrementTTL(WindivertWrapper& wrapper);
void TestHelperEvalFilter(WindivertWrapper& wrapper);
void TestHelperEvalFilter2(WindivertWrapper& wrapper);
void TestHelperFunctions();
void TestWinDivertSend();
int StartNativeTesting();