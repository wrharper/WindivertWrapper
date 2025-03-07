#include "pch.h"
#include "WindivertWrapper.h"
#include <iostream>
#include <stdexcept>

int main() {
    try {
        std::cout << "Creating WindivertWrapper instance" << std::endl;
        WindivertWrapper wrapper;
        std::cout << "WindivertWrapper instance created" << std::endl;

        // If successful, proceed with additional tests
        std::cout << "Initialization successful, proceed with further tests..." << std::endl;

    }
    catch (const std::exception& ex) {
        std::cerr << "Unhandled exception: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "Unhandled unknown exception occurred." << std::endl;
    }

    return 0;
}
