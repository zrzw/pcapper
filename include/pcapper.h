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
