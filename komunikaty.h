#include <vector>
#include <variant>
#include <string>

using namespace std;
struct peer
{
    char peer_address_length;
    string peer_address;
    unsigned short port;
    bool operator<(const peer &other) const {
        return peer_address < other.peer_address;
    }
};

// structure of message sent and received over network
struct message_t
{
    char message;
    unsigned short count;
    vector<peer> peers;
    unsigned long long timestamp;
    unsigned char synchronized;
};

// Message type ids
enum message_type
{
    HELLO = 1,
    HELLO_REPLY = 2,
    CONNECT = 3,
    ACK_CONNECT = 4,
    SYNC_START = 11,
    DELAY_REQUEST = 12,
    DELAY_RESPONSE = 13,
    LEADER = 21,
    GET_TIME = 31,
    TIME = 32
};