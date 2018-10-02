#ifndef _PCAPPER_H_
#define _PCAPPER_H_

#include <queue>
#include <string>
#include <iostream>
#include <pcap.h>

namespace pcapper {
   
    class packet{

    };

    class pcap_session{
    public:
        /* Create pcap session, compile + apply filter then begin listening */
        explicit pcap_session(size_t capture_limit, std::string& filter_str,
                              std::ostream& errstream);
        /* Close the pcap session */
        ~pcap_session();
        friend void libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                                     const u_char *pkt);
    private:
        /* when both locks are held - move write_q into read_q */
        void _with_rw_locks_rebalance();
        std::queue<packet> read_q; // for consumers
        std::queue<packet> write_q; // for libpcap
        pcap_t *handle;
        //char *dev;
        struct bpf_program bpf;
        //const char *filter;
        bpf_u_int32 mask, net;
    };

    void libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                                     const u_char *pkt);
}

#endif
