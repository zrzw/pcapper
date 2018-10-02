#ifndef _PCAPPER_H_
#define _PCAPPER_H_

#include <queue>
#include <string>
#include <iostream>
#include <mutex>
#include <thread>
#include <pcap.h>

namespace pcapper {
   
    class packet{
    public:
        explicit packet(const std::string& s);
    private:
        std::string data;
    };

    class pcap_session{
    public:
        /* Create pcap session, compile + apply filter then begin listening */
        explicit pcap_session(const std::string& filter_str,
                              std::ostream& errstream);
        /* Close the pcap session */
        ~pcap_session();
        friend void libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                                     const u_char *pkt);
    private:
        std::thread _thread;
        /* when both locks are held - move write_q into read_q */
        size_t _with_rw_locks_rebalance();
        std::mutex read_q_mutex;
        std::queue<packet> read_q; // for consumers
        std::mutex write_q_mutex;
        std::queue<packet> write_q; // for libpcap
        pcap_t *handle;
        //char *dev;
        struct bpf_program bpf;
        //const char *filter;
        bpf_u_int32 mask, net;
    };

    void libpcap_callback(u_char *, const struct pcap_pkthdr *, const u_char *);
}

#endif
