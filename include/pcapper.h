/*
** pcapper- libpcap wrapper classes for C++
*/
#ifndef _PCAPPER_H_
#define _PCAPPER_H_

#include <queue>
#include <string>
#include <cstring>
#include <iostream>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <exception>
#include <memory>
#include <pcap.h>

#define _PCAPPER_DEBUG_ true

namespace pcapper {

    class phy_addr{
    public:
        explicit phy_addr(const unsigned char* data){
            memcpy(addr, data, sizeof(addr)); }
        const static size_t PHY_ADDR_LEN=6;
        friend std::ostream& operator<<(std::ostream& os, const phy_addr& pa);
    private:
        unsigned char addr[PHY_ADDR_LEN];
    };
    
    std::ostream& operator<<(std::ostream& os, const phy_addr& pa);

    // Link layer header
    class mac_hdr{
    public:
        virtual ~mac_hdr() = 0;
        virtual phy_addr get_src_addr() = 0;
        virtual phy_addr get_dst_addr() = 0;
    };

    inline mac_hdr::~mac_hdr() {}

    class ethernet_hdr : public mac_hdr{
    public:
        explicit ethernet_hdr(const unsigned char* data);
        ~ethernet_hdr() {}
        phy_addr get_src_addr() { return src; }
        phy_addr get_dst_addr() { return dst; }
        std::string get_printable_ether_type();
        const static size_t MAC_8023_HDR_LEN=14;
        const static size_t SRC_ADDR_OFFSET=6;
        const static size_t DST_ADDR_OFFSET=0;
        const static size_t ET_OFFSET=12;
    private:
        const phy_addr src;
        const phy_addr dst;
        unsigned char ether_type[2];
    };

    class wl_hdr : public mac_hdr{
    public:
        explicit wl_hdr(const unsigned char* data);
        ~wl_hdr() { }
        phy_addr get_src_addr() { return src; }
        phy_addr get_dst_addr() { return dst; }
        const static size_t MAC_80211_HDR_LEN=30;
        const static size_t SRC_ADDR_OFFSET=10;
        const static size_t DST_ADDR_OFFSET=4;
    private:
        const phy_addr src;
        const phy_addr dst;
    };

    // Network Layer header
    class nl_hdr{

    };
    
    class ip_hdr : public nl_hdr{

    };

    class tl_hdr{

    };
   
    class packet{
    public:
        packet() {}
        ~packet() {}
        packet(int ll_type, const u_char* pkt, const struct pcap_pkthdr *hdr);
        packet(packet& r) = delete;
        packet(packet&& r);
        packet& operator=(packet& r) = delete;
        packet& operator=(packet&& r);
        const std::unique_ptr<mac_hdr>& get_machdr() { return machdr; }
    private:
        // Headers
        std::unique_ptr<mac_hdr> machdr; // Link layer
        std::unique_ptr<nl_hdr> nlhdr; // Network layer
        std::unique_ptr<tl_hdr> tlhdr; // Transport layer
    };

    class pcap_session;
    
    class packet_handler{
    public:
        virtual std::queue<packet>& get_queue() = 0;
        virtual std::mutex& get_queue_mutex() = 0;
    };

    class basic_packet_handler : public packet_handler{
    public:
        std::queue<packet>& get_queue() { return packet_q; }
        std::mutex& get_queue_mutex() { return pq_mutex; }
        virtual void pop(pcap_session& pcap);
    protected:
        std::mutex pq_mutex;
        std::queue<packet> packet_q; 
    };
    
    class pcap_setup_ex : public std::exception{
    public:
        explicit pcap_setup_ex(const char* msg_) throw() : msg(msg_) { }
        virtual char const* what() const throw(){
            return msg;
        }
    private:
        const char *msg;
    };
    
    class pcap_session{
    public:
        /* Create pcap session, compile + apply filter then begin listening */
        explicit pcap_session(const std::string& filter_str, packet_handler& ph_);
        /* Close the pcap session */
        ~pcap_session();
        packet_handler& get_handler() {return ph;}
        std::condition_variable& get_packets_available(){return packets_available;}
        friend void libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                                     const u_char *pkt);
#if _PCAPPER_DEBUG_
        std::ostream& serr; // for shared debugging between threads
        std::mutex serr_mutex;
#endif
    private:
        std::thread _thread;

        packet_handler& ph;
        std::condition_variable packets_available;

        /* libpcap variables */
        pcap_t *handle;
        struct bpf_program bpf;
        bpf_u_int32 mask, net;
    };

    /* Callback function to run in thread_ (declared as friend in pcap_session) */
    void libpcap_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
}

#endif
