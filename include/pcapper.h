/*
** pcapper- libpcap wrapper classes for C++
*/
#ifndef _PCAPPER_H_
#define _PCAPPER_H_

#include <queue>
#include <string>
#include <iostream>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <exception>
#include <pcap.h>

#define _PCAPPER_DEBUG_ true

namespace pcapper {
   
    class packet{
    public:
        explicit packet(const std::string& s);
        std::string data;
    };

    class pcap_setup_ex : public std::exception{
    public:
        pcap_setup_ex(const char* msg_) throw() : msg(msg_) { }
        virtual char const* what() const throw(){
            return msg;
        }
    private:
        const char *msg;
    };
    
    class pcap_session{
    public:
        /* Create pcap session, compile + apply filter then begin listening */
        explicit pcap_session(const std::string& filter_str);
        /* Close the pcap session */
        ~pcap_session();
   
        /* Get a copy of one packet from the front of the queue */
        void pop();
        friend void libpcap_callback(u_char *user, const struct pcap_pkthdr *hdr,
                                     const u_char *pkt);
#if _PCAPPER_DEBUG_
        std::ostream& serr; // for shared debugging between threads
        std::mutex serr_mutex;
#endif
    private:
        std::thread _thread;
        std::mutex pq_mutex;
        std::queue<packet> packet_q;   
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
