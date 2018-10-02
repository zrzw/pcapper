/*
** pcapper- libpcap wrapper classes for C++
*/
#include <pcap.h>
#include <string>
#include <iostream>
#include <queue>
#include <mutex>

#include "pcapper.h"

/* Create pcap session, compile + apply filter then begin listening */
pcapper::pcap_session::pcap_session(const std::string& filter,
                                    std::ostream& errstream)
{
    char err[PCAP_ERRBUF_SIZE];
    char* dev = pcap_lookupdev(err); //TODO: use specified (not default) device
    if(dev == nullptr){
        errstream << "Pcapper: Couldn't open default dev" << std::endl;
        exit(1); //TODO: throw
    }
    if(pcap_lookupnet(dev, &net, &mask, err) == -1){
        errstream << "Pcapper: Couldn't get netmask: " << err << std::endl;
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 20, err);
    if(handle == NULL){
        errstream << "Pcapper: Couldn't open " << dev << ": " << err << std::endl;
        exit(1); //TODO: throw
    }
    if((pcap_compile(handle, &bpf, filter.c_str(), 0, net) == -1)
       || (pcap_setfilter(handle, &bpf) == -1)){
        std::cout << "Pcapper: Couldn't parse or set filter" << std::endl;
        exit(1); //TODO: throw
    }
    _thread = std::thread(pcap_loop, handle, -1, libpcap_callback, (u_char*)this);
}

pcapper::pcap_session::~pcap_session()
{
    pcap_breakloop(handle);
    _thread.join();
    pcap_close(handle);
}

void pcapper::libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                          const u_char *pkt)
{
    pcapper::packet p{"test"}; //TODO: construct from pkt
    pcapper::pcap_session* pcap = (pcapper::pcap_session*)user;
    std::unique_lock<std::mutex> wq_lck {pcap->write_q_mutex};
    pcap->write_q.push(p);
    std::unique_lock<std::mutex> rq_lck {pcap->read_q_mutex, std::try_to_lock};
    if(rq_lck){
        //std::cout << "(acquired read_q lock...";
        pcap->_with_rw_locks_rebalance();
        //std::cout << "..moved " << n << " elements..";
        rq_lck.mutex()->unlock();
        //std::cout << "...unlocked read_q lock\n";
    }
}

/*
** Called with both locks held; moves elements from write_q into read_q
** @returns number of elements moved
*/
size_t pcapper::pcap_session::_with_rw_locks_rebalance()
{
    size_t len = 0;
    if(read_q.empty()){
        len = write_q.size();
        read_q = std::move(write_q);
        write_q = {};
    } else {
        while(!write_q.empty()){
            auto p = write_q.front();
            write_q.pop();
            read_q.push(p); //TODO: packet move constructor
            ++len;
        }
    }
    return len;
}

pcapper::packet::packet(const std::string& s)
{
    data = s;
}
