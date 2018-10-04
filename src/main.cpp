#include <iostream>
#include <string>
#include <chrono>
#include "pcapper.h"

using namespace pcapper;

int main(int argc, char** argv)
{
    // basic_packet_handler provides a blocking pop() function which prints all
    // recieved packets to the specified ostream.
    basic_packet_handler handler;

    // pcap_session initiates a pcap_loop (libpcap) in a new thread with the
    // specified filter and queues packets to the designated handler using the
    // libpcap callback mechanism.
    pcap_session pcap {"port 443", handler};
    for(;;)
        handler.pop(pcap);
    return 0;
}
