#include "pch.h"
#include "ExternWindivertWrapperTest.h"
#include "NativeWindivertWrapperTest.h"
#include "AppNetworkMonitor.h" // Include the correct header

static void ShowMenu() {
    std::cout << "Select a test to run:" << std::endl;
    std::cout << "1. Start Extern Testing" << std::endl;
    std::cout << "2. Start Native Testing" << std::endl;
    std::cout << "3. App Testing" << std::endl;
    std::cout << "4. Exit" << std::endl;
}

int main() {
    int choice = 0;
    while (choice != 5) {
        ShowMenu();
        std::cin >> choice;

        switch (choice) {
        case 1:
            StartExternTesting();
            break;
        case 2:
            StartNativeTesting();
            break;
        case 3:
            RunFlowLayerTest();
            break;
        case 4:
            std::cout << "Exiting..." << std::endl;
            break;
        default:
            std::cout << "Invalid choice. Please try again." << std::endl;
            break;
        }
    }
    return 0;
}
