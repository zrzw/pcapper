#include <iostream>
#include <string>
#include "pcapper.h"

using namespace pcapper;

int main(int argc, char** argv)
{
    std::string filter {"port 53"};
    pcap_session {1000, filter, std::cout};
    return 0;
}
