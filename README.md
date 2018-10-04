# pcapper
Super simple C++ libpcap wrapper (in development)

```C++
// basic_packet_handler provides a blocking pop() function which prints all
// recieved packets to the specified ostream.
basic_packet_handler handler;

// pcap_session initiates a pcap_loop (libpcap) in a new thread with the
// specified filter and queues packets to the designated handler using the
// libpcap callback mechanism.
pcap_session pcap {"port 443", handler};
for(;;)
    handler.pop(pcap, std::cout);
```
You can create your own `packet_handler` to process packets in a more meaningful way:

```C++
// from pcapper.h
class packet_handler{
public:
    virtual std::queue<packet>& get_queue() = 0;
    virtual std::mutex& get_queue_mutex() = 0;
};

// your source file
class your_packet_handler : public packet_handler{
public:
    std::queue<packet>& get_queue() { return packet_q; }
    std::mutex& get_queue_mutex() { return pq_mutex; }
    virtual void pop(pcap_session& pcap);
protected:
    std::mutex pq_mutex;
    std::queue<packet> packet_q; 
};
```
then operate on the packet queue as follows:
```C++
void your_packet_handler::f(pcap_session& pcap)
{
    std::unique_lock<std::mutex> qlck {pq_mutex};
    pcap.get_packets_available().wait(qlck); // wait for packets to be queued
    while(!packet_q.empty()){
        auto p = std::move(packet_q.front());
        packet_q.pop();
        // do something with p
    }
}
```
