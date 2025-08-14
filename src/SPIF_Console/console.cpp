#include "ml_pipeline.hpp"
#include <iostream>

int main() {
    std::cout << "Starting ML Pipeline Console\n";
    ml_pipeline::MLPipeline pipeline;
    pipeline.interactive_console();
    std::cout << "Exiting ML Pipeline Console\n";
    return 0;
}