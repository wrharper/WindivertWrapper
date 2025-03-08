#include "pch.h"
#include <iostream>
#include "ExternWindivertWrapperTest.h"
#include "NativeWindivertWrapperTest.h"

void ShowMenu() {
    std::cout << "Select a test to run:" << std::endl;
    std::cout << "1. Start Extern Testing" << std::endl;
    std::cout << "2. Start Native Testing" << std::endl;
    std::cout << "3. Exit" << std::endl;
}

int main() {
    int choice = 0;
    while (choice != 3) {
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
            std::cout << "Exiting..." << std::endl;
            break;
        default:
            std::cout << "Invalid choice. Please try again." << std::endl;
            break;
        }
    }
    return 0;
}
