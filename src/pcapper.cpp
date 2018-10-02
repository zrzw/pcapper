/*
** pcapper- libpcap wrapper classes for C++
*/
#include <pcap.h>
#include <string>
#include <iostream>
#include <queue>
#include "pcapper.h"

/* Create pcap session, compile + apply filter then begin listening */
pcapper::pcap_session::pcap_session(size_t capture_limit, std::string& filter,
                                    std::ostream& errstream)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = pcap_lookupdev(errbuf); //TODO: use specified (not default) device
    if(dev == nullptr){
        errstream << "Pcapper: Couldn't open default dev" << std::endl;
        exit(1); //TODO: throw
    }
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1){
        errstream << "Pcapper: Couldn't get netmask: " << errbuf << std::endl;
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == NULL){
        errstream << "Pcapper: Couldn't open " << dev << ": " << errbuf << std::endl;
        exit(1); //TODO: throw
    }
    if((pcap_compile(handle, &bpf, filter.c_str(), 0, net) == -1)
       || (pcap_setfilter(handle, &bpf) == -1)){
        std::cout << "Pcapper: Couldn't parse or set filter" << std::endl;
        exit(1); //TODO: throw
    }
    pcap_loop(handle, capture_limit, pcapper::libpcap_callback, NULL);
}

pcapper::pcap_session::~pcap_session()
{
    pcap_close(handle);
}

void pcapper::libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                          const u_char *pkt)
{
    std::cout << "Rx\n";
}
