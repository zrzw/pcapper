/*
** pcapper- libpcap wrapper classes for C++
*/
#include <pcap.h>
#include <string>
#include <iostream>
#include <queue>
#include <cassert>
#include <mutex>

#include "pcapper.h"

#define _PCAPPER_DEBUG_ true

/* Create pcap session, compile + apply filter then begin listening */
pcapper::pcap_session::pcap_session(const std::string& filter,
                                    std::ostream& errstream)
    :serr {errstream}
{
    char err[PCAP_ERRBUF_SIZE];
    char* dev = pcap_lookupdev(err); //TODO: use specified (not default) device
    if(dev == nullptr){
        serr << "Pcapper: Couldn't open default dev" << std::endl;
        exit(1); //TODO: throw
    }
    if(pcap_lookupnet(dev, &net, &mask, err) == -1){
        serr << "Pcapper: Couldn't get netmask: " << err << std::endl;
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 20, err);
    if(handle == NULL){
        serr << "Pcapper: Couldn't open " << dev << ": " << err << std::endl;
        exit(1); //TODO: throw
    }
    if((pcap_compile(handle, &bpf, filter.c_str(), 0, net) == -1)
       || (pcap_setfilter(handle, &bpf) == -1)){
        serr << "Pcapper: Couldn't parse or set filter" << std::endl;
        exit(1); //TODO: throw
    }
    _thread = std::thread(pcap_loop, handle, -1, libpcap_callback, (u_char*)this);
}

pcapper::pcap_session::~pcap_session()
{
    pcap_breakloop(handle);
    #if _PCAPPER_DEBUG_
    std::unique_lock<std::mutex> errlck {serr_mutex};
    serr << "Pcapper: attempting to join()...";
    #endif
    _thread.join();
    #if _PCAPPER_DEBUG_
    serr << "..joined" << std::endl;
    #endif
    pcap_close(handle);
}

void pcapper::pcap_session::pop()
{
    std::unique_lock<std::mutex> qlck {pq_mutex};
    packets_available.wait(qlck); // wait for packets to be queued
    assert(!packet_q.empty());
    while(!packet_q.empty()){
        auto p = packet_q.front();
        packet_q.pop();
        //TODO: do something with p
#if _PCAPPER_DEBUG_
        std::unique_lock<std::mutex> errlck {serr_mutex};
        serr << "Pcapper: pcap_session::pop(): removed 1, " << packet_q.size();
        serr << " packets still queued" << std::endl;
        errlck.unlock();
#endif
    }
    qlck.unlock();
}

void pcapper::libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                          const u_char *pkt)
{
    pcapper::packet p{"test"}; //TODO: construct from pkt
    pcapper::pcap_session* pcap = (pcapper::pcap_session*)user;
    std::unique_lock<std::mutex> lck {pcap->pq_mutex};
    #if _PCAPPER_DEBUG_
    std::unique_lock<std::mutex> errlck {pcap->serr_mutex};
    pcap->serr << "Pcapper: pcapper::libpcap_callback(): adding packet to queue, ";
    pcap->serr << "total=" << pcap->packet_q.size()+1 << std::endl;
    errlck.unlock();
    #endif
    pcap->packet_q.push(p);
    lck.unlock();
    pcap->packets_available.notify_one();
}

pcapper::packet::packet(const std::string& s)
{
    data = s;
}
