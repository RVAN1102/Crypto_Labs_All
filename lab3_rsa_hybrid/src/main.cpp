#include "cli.hpp"

#include <cryptlib.h>

#include <exception>
#include <iostream>

int main(int argc, char* argv[]) {
    try {
        return run_command(argc, argv);
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ error: " << e.what() << "\n";
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
