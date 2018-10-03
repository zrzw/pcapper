#include <iostream>
#include <string>
#include <chrono>
#include "pcapper.h"

using namespace pcapper;

#define TEST false

int main(int argc, char** argv)
{
    pcap_session ps {"port 53", std::cerr};
    if(TEST){
        std::this_thread::sleep_for(std::chrono::milliseconds{3000});
        std::cout << "Timer elapsed\n";
    } else {
        for(;;){
            ps.pop();
        }
    }
    return 0;
}
