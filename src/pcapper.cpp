/*
** pcapper- libpcap wrapper classes for C++
*/
#include <pcap.h>
#include <string>
#include <cstring>
#include <iostream>
#include <queue>
#include <cassert>
#include <mutex>
#include <iomanip>

#include "pcapper.h"

using namespace pcapper;

std::ostream& pcapper::operator<<(std::ostream& os, const phy_addr& pa)
{
    char fill = os.fill('0');
    for(int i=0; i<6; ++i){
        os << std::setw(2) << std::hex << (unsigned int)pa.addr[i];
        if(i != 5) os << ":";
    }
    os << std::dec;
    os.fill(fill);
    return os;
}

ethernet_hdr::ethernet_hdr(const unsigned char* data)
    : src(phy_addr(data+SRC_ADDR_OFFSET)), dst(phy_addr(data+DST_ADDR_OFFSET))
{
    memcpy(ether_type, data+ET_OFFSET, 2);
}

std::string ethernet_hdr::get_printable_ether_type()
{
    std::ostringstream oss;
    oss.fill('0');
    oss << "0x" << std::hex << std::setw(2) <<(unsigned int)ether_type[0];
    oss << std::setw(2) << (unsigned int) ether_type[1];
    return oss.str();
}

wl_hdr::wl_hdr(const unsigned char* data)
    : src(phy_addr(data+SRC_ADDR_OFFSET)), dst(phy_addr(data+DST_ADDR_OFFSET)){}

packet::packet(int ll_type, const u_char* pkt, const struct pcap_pkthdr *hdr)
{
    size_t len = (hdr->len < hdr->caplen) ? hdr->len : hdr->caplen;
    size_t cnt = 0; //bytes processed of this packet so far
    switch(ll_type){
    case(DLT_EN10MB):
        // be aware of "fake ethernet" packets: https://wiki.wireshark.org/Wi-Fi
        if(len < ethernet_hdr::MAC_8023_HDR_LEN)
            throw pcap_setup_ex("Pcapper: malformed ethernet header");
        machdr = std::unique_ptr<mac_hdr>{new ethernet_hdr(pkt)};
        break;
    case(DLT_IEEE802_11):
        if(len < wl_hdr::MAC_80211_HDR_LEN)
            throw pcap_setup_ex("Pcapper: malformed 802.11 header"); //TODO: excep
        machdr = std::unique_ptr<mac_hdr>{new wl_hdr(pkt)};
        cnt += wl_hdr::MAC_80211_HDR_LEN;
        break;
    default:
        throw pcap_setup_ex("Pcapper: unfamiliar link-layer header");
    };
    //TODO parse network and transport headers
}

packet::packet(packet&& r)
{
    if(this != &r){
        machdr = std::move(r.machdr);
        nlhdr = std::move(r.nlhdr);
        tlhdr = std::move(r.tlhdr);
    }
}

packet& packet::operator= (packet&& r)
{
    if(this != &r){
        machdr = std::move(r.machdr);
        nlhdr = std::move(r.nlhdr);
        tlhdr = std::move(r.tlhdr);
    }
    return *this;
}

void basic_packet_handler::pop(pcap_session& pcap)
{
    std::unique_lock<std::mutex> qlck {pq_mutex};
    pcap.get_packets_available().wait(qlck); // wait for packets to be queued
    assert(!packet_q.empty());
    while(!packet_q.empty()){
        auto p = std::move(packet_q.front());
        packet_q.pop();
        //TODO: do something with p
#if _PCAPPER_DEBUG_
        std::unique_lock<std::mutex> errlck {pcap.serr_mutex};
        pcap.serr << "Pcapper: basic_packet_handler::pop(): removed 1, ";
        ethernet_hdr& eh = dynamic_cast<ethernet_hdr&>(*p.get_machdr());
        pcap.serr << "[dst=" << p.get_machdr()->get_dst_addr() << ",";
        pcap.serr << "type=" << eh.get_printable_ether_type() << "]. ";
        pcap.serr << packet_q.size();
        pcap.serr << " packets still queued" << std::endl;
        errlck.unlock();
#endif
    }
    qlck.unlock();
}

/* Create pcap session, compile + apply filter then begin listening */
pcap_session::pcap_session(const std::string& filter, packet_handler& ph_)
#if _PCAPPER_DEBUG_
    : serr(std::cerr), ph(ph_)
#else
      : ph(ph_)
#endif
{
    char err[PCAP_ERRBUF_SIZE];
    char* dev = pcap_lookupdev(err); //TODO: use specified (not default) device
    if(dev == nullptr){
        throw pcap_setup_ex(err);
    }
    if(pcap_lookupnet(dev, &net, &mask, err) == -1){
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(dev, BUFSIZ, 1, 20, err);
    if(handle == NULL){
        throw pcap_setup_ex(err);
    }
    if((pcap_compile(handle, &bpf, filter.c_str(), 0, net) == -1)
       || (pcap_setfilter(handle, &bpf) == -1)){
        throw pcap_setup_ex(err);
    }
    _thread = std::thread(pcap_loop, handle, -1, libpcap_callback, (u_char*)this);
}

pcap_session::~pcap_session()
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

void pcapper::libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                               const u_char *pkt)
{
    pcap_session* pcap = (pcap_session*)user;
    // create a temporary packet representation from the libpcap capture
    packet p{pcap_datalink(pcap->handle), pkt, hdr};
    // get access to the queue and it's mutex
    packet_handler& ph = pcap->get_handler();
    std::unique_lock<std::mutex> lck {ph.get_queue_mutex()};
    ph.get_queue().push(std::move(p));
#if _PCAPPER_DEBUG_
    size_t len = ph.get_queue().size();
#endif
    lck.unlock();
#if _PCAPPER_DEBUG_
    std::unique_lock<std::mutex> errlck {pcap->serr_mutex};
    pcap->serr << "Pcapper: pcapper::libpcap_callback(): added packet to queue, ";
    pcap->serr << "total=" << len << std::endl;
    errlck.unlock();
#endif
    pcap->packets_available.notify_one();
}
