#include "sigtool/cli.hpp"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        return sigtool::run_cli(argc, argv);
    } catch (const std::exception& ex) {
        std::cerr << "error: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "error: unexpected failure\n";
        return 1;
    }
}
