#include "pch.h"

// Declare the packet queue and synchronization primitives

void TestWinDivertOpenAndCloseEx();
void TestWinDivertRecvEx();
void TestHelperCalcChecksumsEx(WindivertWrapper& wrapper);
void TestHelperDecrementTTLEx(WindivertWrapper& wrapper);
void TestHelperEvalFilterEx(WindivertWrapper& wrapper);
void TestHelperEvalFilter2Ex(WindivertWrapper& wrapper);
bool TestCompileFilterEx(WindivertWrapper& wrapper);
void TestHelperFunctionsEx();
void TestWinDivertSendEx();
int StartExternTesting();

void TestBlockSpecificIPEx();