#pragma once

#include "WindivertWrapper.h"

void TestWinDivertOpenAndCloseEx();
void TestWinDivertRecvEx();
void TestHelperCalcChecksumsEx(WindivertWrapper& wrapper);
void TestHelperDecrementTTLEx(WindivertWrapper& wrapper);
void TestHelperEvalFilterEx(WindivertWrapper& wrapper);
void TestHelperEvalFilter2Ex(WindivertWrapper& wrapper);
void TestHelperFunctionsEx();
void TestWinDivertSendEx();
int StartExternTesting();

void TestBlockSpecificIPEx();