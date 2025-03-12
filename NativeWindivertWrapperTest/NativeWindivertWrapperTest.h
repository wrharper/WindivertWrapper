#include "pch.h"

void TestWinDivertOpenAndClose();
void TestWinDivertRecv();
void TestHelperCalcChecksums(WindivertWrapper& wrapper);
void TestHelperDecrementTTL(WindivertWrapper& wrapper);
void TestHelperEvalFilter(WindivertWrapper& wrapper);
void TestHelperEvalFilter2(WindivertWrapper& wrapper);
void TestHelperFunctions();
void TestWinDivertSend();
bool TestCompileFilter(WindivertWrapper& wrapper);
int StartNativeTesting();