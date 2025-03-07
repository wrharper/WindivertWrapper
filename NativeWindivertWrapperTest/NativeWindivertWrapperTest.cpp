#include "pch.h"
#include "WindivertWrapper.h"
#include <iostream>
#include <stdexcept>
#include <Windows.h>
#include <string> // Include the string header for std::to_string

int main() {
    HMODULE hWinDivert = LoadLibrary(TEXT("WinDivert.dll"));
    if (!hWinDivert) {
        DWORD error = GetLastError();
        std::cerr << "Failed to load WinDivert.dll. Error: " << std::to_string(error) << std::endl;
        return 1;
    }

    std::cout << "WinDivert.dll loaded successfully at startup" << std::endl;

    try {
        std::cout << "Creating WindivertWrapper instance for TestInitialization" << std::endl;
        WindivertWrapper wrapper;
        std::cout << "WindivertWrapper instance created for TestInitialization" << std::endl;

        HANDLE handle = wrapper.Open("outbound and ip", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF);
        if (handle != INVALID_HANDLE_VALUE) {
            std::cout << "Open: Success" << std::endl;
            wrapper.Close();
        }
        else {
            DWORD error = GetLastError();
            std::cerr << "Open: Failed. Error: " << std::to_string(error) << std::endl;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "Exception in TestInitialization: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unknown exception occurred in TestInitialization." << std::endl;
    }

    FreeLibrary(hWinDivert);
    std::cout << "Press Enter to exit...";
    std::cin.get();

    return 0;
}
