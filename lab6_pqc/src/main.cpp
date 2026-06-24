#include "pqtool/cli.hpp"

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
    try {
        return pqtool::run_cli(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "ERROR: " << error.what() << '\n';
        return 2;
    }
}
