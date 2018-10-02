#include <iostream>
#include <string>
#include <chrono>
#include "pcapper.h"

using namespace pcapper;

int main(int argc, char** argv)
{
    pcap_session ps {"port 53", std::cerr};
    std::this_thread::sleep_for(std::chrono::milliseconds{3000});
    std::cout << "Timer elapsed\n";
    return 0;
}
