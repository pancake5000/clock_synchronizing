#include <vector>
#include <variant>
#include <string>

using namespace std;
typedef struct
{
    char peer_address_length;
    string peer_address;
    unsigned short port;
} peer;

// structure of message sent and received over network
typedef struct
{
    char message;
    unsigned short count;
    vector<peer> peers;
    unsigned long long timestamp;
    char synchronized;
} message_t;

// Message type ids
typedef enum
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
} message_type;