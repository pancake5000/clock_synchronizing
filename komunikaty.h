#include <vector>

typedef struct
{
    char peer_address_length;
    std::vector<char> peer_address;
    unsigned short port;
} peer;

typedef struct{

}nodata_t;

typedef struct
{
    unsigned long long timestamp;
    char sychronized;
} timestamp_t;

typedef struct
{
   unsigned short count;
   std::vector<peer> peers;
} peers_t;

typedef union
{
    nodata_t nodata;
    timestamp_t timestamp;
    peers_t peers;
} message_data;

typedef struct
{
    char message;
    message_data data;
} message_t;