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

// contents of HELLO, CONNECT, ACK_CONNECT, DELAY_REQUEST, GET_TIME messages
typedef struct
{

} no_data_t;

// contents of TIME, SYNC_START, DELAY_RESPONSE messages
typedef struct
{
    unsigned long long timestamp;
    char sychronized;
} timestamp_t;

// contents of HELLO_REPLY message
typedef struct
{
    unsigned short count;
    vector<peer> peers;
} peers_t;

// contents of LEADER message
typedef struct leader_t
{
    char synchronized;
} leader_t;

typedef std::variant
<
    no_data_t,
    timestamp_t,
    peers_t,
    leader_t
> message_data;

// structure of message sent and received over network
typedef struct
{
    char message;
    message_data data;
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