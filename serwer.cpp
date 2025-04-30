#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cerrno>
#include <endian.h> // Use endian.h for htonll and ntohll
#include <set>
#include <chrono>
#include <map>

#include "komunikaty.h"
#include "err.h"

#define MAX_DATAGRAM_SIZE 65507 // Maximum size of a UDP datagram
#define IP_ADDRESS_LENGTH 4
#define PEER_DESCRIPTION_SIZE 7 // 1 byte for length + 4 bytes for IP + 2 bytes for port

using namespace std;

struct relation_data
{
    chrono::time_point<chrono::high_resolution_clock> last_sync_start_time;
    chrono::time_point<chrono::high_resolution_clock> last_delay_request_time;
    bool expected_request;
    bool expected_response;
    bool expected_hello_reply;
    bool expected_ack_connect;
};

chrono::time_point<chrono::high_resolution_clock> time0;
unsigned long long offset;
int read_from_argv(int argc, char *argv[], string &bind_address, int &port, string &peer_address, int &peer_port)
{
    int opt;
    bool got_peer = 0;
    bool got_peer_port = 0;
    while ((opt = getopt(argc, argv, "b:p:a:r:")) != -1)
    {
        switch (opt)
        {
        case 'b':
        {
            if (optarg == nullptr)
            {
                cerr << "Error: Bind address is required." << endl;
                return 1;
            }
            bind_address = optarg;
            // Validate the bind address format (IPv4)
            struct sockaddr_in sa;
            if (inet_pton(AF_INET, bind_address.c_str(), &(sa.sin_addr)) == 0)
            {
                cerr << "Error: Invalid bind address format. Must be a valid IPv4 address." << endl;
                return 1;
            }
            break;
        }
        case 'p':
        {
            if (optarg == nullptr)
            {
                cerr << "Error: Port is required." << endl;
                return 1;
            }
            int tmp_port = 0;
            try
            {
                tmp_port = std::stoi(optarg);
            }
            catch (const std::invalid_argument &e)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            catch (const std::out_of_range &e)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            port = tmp_port;
            if (port < 0 || port > 65535)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            break;
        }
        case 'a':
        {
            if (optarg == nullptr)
            {
                cerr << "Error: No peer adsress" << endl;
                return 1;
            }
            got_peer = 1;
            peer_address = optarg;
            struct sockaddr_in sa;
            if (inet_pton(AF_INET, peer_address.c_str(), &(sa.sin_addr)) == 0)
            {
                cerr << "Error: Invalid bind address format. Must be a valid IPv4 address." << endl;
                return 1;
            }
            break;
        }
        case 'r':
        {
            if (optarg == nullptr)
            {
                cerr << "Error: Peer port is required." << endl;
                return 1;
            }
            got_peer_port = 1;
            int tmp_port = 0;
            try
            {
                tmp_port = std::stoi(optarg);
            }
            catch (const std::invalid_argument &e)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            catch (const std::out_of_range &e)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            peer_port = tmp_port;
            if (peer_port < 0 || peer_port > 65535)
            {
                cerr << "Error: Invalid port number." << endl;
                return 1;
            }
            break;
        }
        default:
        {
            cerr << "Error: Invalid option: " << (char)opt << endl;
            return 1;
        }
        }
    }
    if (got_peer != got_peer_port)
    {
        cerr << "Error: Peer address and port must be provided together." << endl;
        return 1;
    }
    // Optional: Print the parsed values for debugging
    cout << "Bind Address: " << bind_address << endl;
    cout << "Port: " << port << endl;
    cout << "Peer Address: " << peer_address << endl;
    cout << "Peer Port: " << peer_port << endl;
    return 0;
}
int initialize_socket(int &server_socket, sockaddr_in &server_addr, string bind_address, int port)
{
    server_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (server_socket < 0)
    {
        cerr << "Error creating socket: " << strerror(errno) << endl;
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(bind_address.c_str());

    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        cerr << "Error binding socket: " << strerror(errno) << endl;
        return 1;
    }

    cout << "Server socket initialized and bound to " << bind_address << ":" << port << endl;
    return 0;
}

unsigned long long time_natural()
{
    auto now = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(now - time0);
    return duration.count();
}
unsigned long long time_offset()
{
    auto now = chrono::high_resolution_clock::now();
    auto duration = chrono::duration_cast<chrono::milliseconds>(now - time0);
    return (unsigned long long)duration.count() - offset;
}
message_t new_message(int message_type)
{
    message_t message;
    message.message = message_type;
    message.count = 0;
    message.timestamp = 0;
    message.synchronized = 255;
    return message;
}
relation_data new_relation_data()
{
    relation_data data;
    data.expected_request = false;
    data.expected_response = false;
    data.expected_hello_reply = false;
    data.expected_ack_connect = false;
    return data;
}
int serialize(message_t message, char *buf)
{
    int size = 1;
    buf[0] = message.message;
    switch (message.message)
    {
    case HELLO_REPLY:
    {
        unsigned short value = htons(message.count);     // Convert to network byte order
        memcpy(buf + 1, &value, sizeof(unsigned short)); // Copy to buffer starting at position 1
        size += sizeof(unsigned short);                  // Update size
        for (int i = 0; i < message.count; i++)
        {
            buf[size] = message.peers[i].peer_address_length;
            size++;
            memcpy(buf + size, message.peers[i].peer_address.c_str(), message.peers[i].peer_address_length); // Copy address
            size += message.peers[i].peer_address_length;                                                    // Update size
            unsigned short port_value = htons(message.peers[i].port);                                        // Convert to network byte order
            memcpy(buf + size, &port_value, sizeof(unsigned short));                                         // Copy to buffer starting at position size
            size += sizeof(unsigned short);                                                                  // Update size
        }
        break;
    }
    case SYNC_START:
    case DELAY_RESPONSE:
    case TIME:
    {
        unsigned long long value = htobe64(message.timestamp);   // Convert to network byte order
        memcpy(buf + size, &value, sizeof(unsigned long long));  // Copy to buffer starting at position size
        size += sizeof(unsigned long long);                      // Update size
        memcpy(buf + size, &message.synchronized, sizeof(char)); // Copy synchronized flag
        size += sizeof(char);                                    // Update size
    }
    }
    return size;
}
int deserialize(message_t &message, char *buf, int size)
{
    if (size < 1)
    {
        cerr << "Error: Buffer size is too small to deserialize message." << endl;
        return -1;
    }
    message.message = buf[0];
    int pos = 1;
    switch (message.message)
    {
    case HELLO_REPLY:
    {
        if (size - pos < (int)sizeof(unsigned short))
        {
            cerr << "Error: Buffer size is too small to deserialize message." << endl;
            return -1;
        }
        message.count = ntohs(*(unsigned short *)(buf + pos)); // Convert from network byte order
        pos += sizeof(unsigned short);                         // Update position
        if (size - pos < (int)message.count * (PEER_DESCRIPTION_SIZE))
        {
            cerr << "Error: Buffer size is too small to deserialize message." << endl;
            return -1;
        }
        // Resize vector to hold peers
        for (int i = 0; i < message.count; i++)
        {
            message.peers[i].peer_address_length = buf[pos]; // Read address length
            pos++;
            if (message.peers[i].peer_address_length != IP_ADDRESS_LENGTH)
            {
                cerr << "Error: Invalid peer address length." << endl;
                return -1;
            }
            message.peers[i].peer_address = string(buf + pos, message.peers[i].peer_address_length); // Read address
            pos += message.peers[i].peer_address_length;                                             // Update position
            message.peers[i].port = ntohs(*(unsigned short *)(buf + pos));                           // Convert from network byte order
            pos += sizeof(unsigned short);                                                           // Update position
        }
        break;
    }
    case SYNC_START:
    case DELAY_RESPONSE:
    case TIME:
    {
        if (size - pos < (int)sizeof(unsigned long long) + (int)sizeof(char))
        {
            cerr << "Error: Buffer size is too small to deserialize message." << endl;
            return -1;
        }
        message.timestamp = be64toh(*(unsigned long long *)(buf + pos)); // Convert from network byte order
        pos += sizeof(unsigned long long);                               // Update position
        message.synchronized = *(char *)(buf + pos);                     // Read synchronized flag
        pos += sizeof(char);                                             // Update position
    }
    }
    return 0;
}

int send_message(message_t message, int socket, string receiver_address, int receiver_port, char *buf)
{
    int size = serialize(message, buf);
    sockaddr_in peer_addr{};
    peer_addr.sin_family = AF_INET;
    peer_addr.sin_port = htons(receiver_port);
    peer_addr.sin_addr.s_addr = inet_addr(receiver_address.c_str());

    if (sendto(socket, buf, size, 0, (struct sockaddr *)&peer_addr, sizeof(peer_addr)) < 0)
    {
        cerr << "Error sending message to peer: " << strerror(errno) << endl;
        return -1;
    }
    return 0;
}
int receive_message(message_t &message, sockaddr *sender_address, int socket, char *buf)
{
    socklen_t addr_len = sizeof(sender_address);
    ssize_t bytes_received = recvfrom(socket, buf, MAX_DATAGRAM_SIZE, MSG_DONTWAIT, (struct sockaddr *)sender_address, &addr_len);
    if (bytes_received < 0)
    {
        if(errno == EAGAIN || errno == EWOULDBLOCK)
        {
            message = new_message(NO_MSG);
            return 0; // No data received, non-blocking mode
        }
        cerr << "Error receiving message: " << strerror(errno) << endl;
        return -1;
    }
    if (deserialize(message, buf, bytes_received) < 0)
    {
        return -1;
    }
    return 0;
}

int say_hello(int socket, string receiver_address, int receiver_port, char *buf)
{
    message_t message = new_message(HELLO);
    if (send_message(message, socket, receiver_address, receiver_port, buf) < 0)
    {
        return -1;
    }
    return 0;
}

void handle_hello(const sockaddr_in &sender_addr, map<peer, relation_data> &relations, int socket, char *buf)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (relations.find(sender) != relations.end())
    {
        relations.erase(sender);
    }
    message_t hello_reply = new_message(HELLO_REPLY);
    hello_reply.count = relations.size();
    hello_reply.peers = vector<peer>();
    for (const auto &relation : relations)
    {
        hello_reply.peers.push_back(relation.first);
    }
    if (send_message(hello_reply, socket, sender.peer_address, sender.port, buf) < 0)
    {
        err_msg("Error sending hello reply");
    }
    relations[sender] = new_relation_data();
}

void handle_hello_reply(const message_t &message, const sockaddr_in &sender_addr, map<peer, relation_data> &relations, string bind_address, int my_port, int socket, char *buf)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (relations.find(sender) != relations.end())
    {
        err_msg("Sender in list of known vertices");
        return;
    }
    peer me = {IP_ADDRESS_LENGTH, bind_address, (unsigned short)my_port};
    if (relations.find(me) != relations.end())
    {
        err_msg("I am in list of known vertices");
        return;
    }
    for (int i = 0; i < message.count; i++)
    {
        peer new_peer = message.peers[i];
        new_peer.port = ntohs(new_peer.port);
        relations[new_peer] = new_relation_data();
        relations[new_peer].expected_ack_connect = true;
        message_t connect_message = new_message(CONNECT);
        if (send_message(connect_message, socket, new_peer.peer_address, new_peer.port, buf) < 0)
        {
            err_msg("Error sending connect message");
        }
    }
    relations[sender] = new_relation_data();
}

void handle_connect(const sockaddr_in &sender_addr, map<peer, relation_data> &relations, int socket, char *buf)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (relations.find(sender) != relations.end())
    {
        err_msg("Sender in list of known vertices");
        return;
    }
    relations[sender] = new_relation_data();
    message_t ack_connect = new_message(ACK_CONNECT);
    if (send_message(ack_connect, socket, sender.peer_address, sender.port, buf) < 0)
    {
        err_msg("Error sending ACK_CONNECT message");
    }
}

void handle_ack_connect(const sockaddr_in &sender_addr, map<peer, relation_data> &relations)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (relations.find(sender) != relations.end())
    {
        err_msg("Sender in list of known vertices");
        return;
    }
    relations[sender] = new_relation_data();
}

void handle_sync_start(const message_t &message, const sockaddr_in &sender_addr, map<peer, relation_data> &relations, unsigned char &sync_level, string current_parent, bool &currently_syncing, chrono::time_point<chrono::high_resolution_clock> &last_sync_start_from_new, unsigned long long &T1, unsigned long long &T3, int socket, char *buf)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (sync_level == 0)
    {
        err_msg("Node is a leader");
        return;
    }
    if (relations.find(sender) == relations.end())
    {
        err_msg("Unknown sender");
        return;
    }
    if (message.synchronized == 255)
    {
        err_msg("Sender not synchronized with leader");
        return;
    }
    if (sender.peer_address == current_parent && message.synchronized >= sync_level)
    {
        err_msg("Parent no longer synchronized");
        current_parent = "";
        sync_level = 255;
        return;
    }
    if (message.synchronized + 1 >= sync_level && sender.peer_address != current_parent)
    {
        err_msg("Sender not better than current sync level");
        return;
    }
    if (currently_syncing)
    {
        err_msg("Already syncing with another peer");
        return;
    }
    if (current_parent != sender.peer_address)
    {
        currently_syncing = true;
        last_sync_start_from_new = chrono::high_resolution_clock::now();
    }
    T1 = message.timestamp;
    relations[sender].expected_response = true;

    message_t delay_request = new_message(DELAY_REQUEST);
    relations[sender].last_delay_request_time = chrono::high_resolution_clock::now();

    T3 = time_natural();
    if (send_message(delay_request, socket, sender.peer_address, sender.port, buf) < 0)
    {
        err_msg("Error sending DELAY_REQUEST message");
    }
}

void handle_delay_request(const sockaddr_in &sender_addr, map<peer, relation_data> &relations, int socket, char *buf)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (relations.find(sender) == relations.end())
    {
        err_msg("Unknown sender");
        return;
    }
    if (relations[sender].expected_request == false)
    {
        err_msg("Request not expected");
        return;
    }
    if (chrono::high_resolution_clock::now() - relations[sender].last_sync_start_time > chrono::seconds(10))
    {
        err_msg("Delay request timeout");
        return;
    }

    message_t delay_response = new_message(DELAY_RESPONSE);
    delay_response.timestamp = time_offset();
    if (send_message(delay_response, socket, sender.peer_address, sender.port, buf) < 0)
    {
        err_msg("Error sending DELAY_RESPONSE message");
    }
}

void handle_delay_response(const message_t &message, const sockaddr_in &sender_addr, map<peer, relation_data> &relations, unsigned char &sync_level, string &current_parent, unsigned long long T1, unsigned long long T2, unsigned long long T3)
{
    if (message.synchronized > sync_level)
    {
        err_msg("Sender worse than current sync level");
        return;
    }
    {
        err_msg("Sender not synchronized with leader");
        return;
    }
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    if (relations.find(sender) == relations.end())
    {
        err_msg("Unknown sender");
        return;
    }
    if (relations[sender].expected_response == false)
    {
        err_msg("Response not requested");
        return;
    }
    if (chrono::high_resolution_clock::now() - relations[sender].last_delay_request_time > chrono::seconds(10))
    {
        err_msg("Delay response timeout");
        return;
    }
    unsigned long long T4 = message.timestamp;
    offset = (T2 - T1 + T3 - T4) / 2;
    sync_level = message.synchronized + 1;
    relations[sender].expected_response = false;
    current_parent = sender.peer_address;
}

void handle_leader(const message_t &message, unsigned char &sync_level)
{
    if (message.synchronized == 0)
    {
        if (sync_level == 0)
        {
            err_msg("Node is already a leader");
        }
    }
    if (message.synchronized == 255)
    {
        if (sync_level != 0)
        {
            err_msg("Node is not a leader");
        }
        else
        {
            sync_level = 255;
        }
    }
}

void handle_get_time(const sockaddr_in &sender_addr, unsigned char sync_level, int socket, char *buf)
{
    peer sender = {IP_ADDRESS_LENGTH, inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port)};
    message_t time_message = new_message(TIME);
    time_message.synchronized = sync_level;
    if (sync_level == 255 || sync_level == 0)
    {
        time_message.timestamp = time_natural();
    }
    else
    {
        time_message.timestamp = time_offset();
    }
    if (send_message(time_message, socket, sender.peer_address, sender.port, buf) < 0)
    {
        err_msg("Error sending TIME message");
    }
}

void handle_time()
{
    err_msg("Received TIME message");
}
void send_sync_starts(map<peer, relation_data> &relations, char sync_level, int socket, char *buf)
{
    for (auto &relation : relations)
    {
        peer sender = relation.first;
        relation.second.last_sync_start_time = chrono::high_resolution_clock::now();
        relation.second.expected_request = true;
        message_t sync_start = new_message(SYNC_START);
        sync_start.synchronized = sync_level;
        sync_start.timestamp = time_offset();
        if (send_message(sync_start, socket, sender.peer_address, sender.port, buf) < 0)
        {
            err_msg("Error sending SYNC_START message");
        }
    }
}
int handle_messages(int socket, char *buf, string bind_address, int my_port)
{
    map<peer, relation_data> relations;
    unsigned char sync_level = 255;
    string current_parent = "";
    unsigned long long T1, T2, T3;

    bool currently_syncing = false;
    string syncing_with = "";

    chrono::time_point<chrono::high_resolution_clock> last_sync_broadcast_time = chrono::high_resolution_clock::now();
    chrono::time_point<chrono::high_resolution_clock> last_sync_from_parent = chrono::high_resolution_clock::now();
    chrono::time_point<chrono::high_resolution_clock> last_sync_start_from_new = chrono::high_resolution_clock::now();
    send_sync_starts(relations, sync_level, socket, buf);

    while (true)
    {

        if (chrono::high_resolution_clock::now() - last_sync_start_from_new > chrono::seconds(10))
        {
            currently_syncing = false;
        }
        if (sync_level!= 0 && sync_level < 255 && chrono::high_resolution_clock::now() - last_sync_from_parent > chrono::seconds(28))
        {
            sync_level = 255;
            current_parent = "";
        }
        if (chrono::high_resolution_clock::now() - last_sync_broadcast_time > chrono::seconds(6))
        {
            last_sync_broadcast_time = chrono::high_resolution_clock::now();
            send_sync_starts(relations, sync_level, socket, buf);
        }
        sockaddr_in sender_addr{};
        message_t message;
        if (receive_message(message, (struct sockaddr *)&sender_addr, socket, buf) < 0)
        {
            return -1;
        }
        if(message.message != NO_MSG)
        {
            cout << "Received message from " << inet_ntoa(sender_addr.sin_addr) << ":" << ntohs(sender_addr.sin_port) << endl;
            cout << "Message type: " << (int)message.message << endl;
        }
        switch (message.message)
        {
        case HELLO:
            cout << "Received HELLO message" << endl;
            handle_hello(sender_addr, relations, socket, buf);
            break;
        case HELLO_REPLY:
            cout << "Received HELLO_REPLY message" << endl;
            handle_hello_reply(message, sender_addr, relations, bind_address, my_port, socket, buf);
            break;
        case CONNECT:
            cout << "Received CONNECT message" << endl;
            handle_connect(sender_addr, relations, socket, buf);
            break;
        case ACK_CONNECT:
            cout << "Received ACK_CONNECT message" << endl;
            handle_ack_connect(sender_addr, relations);
            break;
        case SYNC_START:
            cout << "Received SYNC_START message" << endl;
            T2 = time_natural();
            handle_sync_start(message, sender_addr, relations, sync_level, current_parent, currently_syncing,last_sync_start_from_new, T1, T3, socket, buf);
            break;
        case DELAY_REQUEST:
            handle_delay_request(sender_addr, relations, socket, buf);
            cout << "Received DELAY_REQUEST message" << endl;
            break;
        case DELAY_RESPONSE:
            cout << "Received DELAY_RESPONSE message" << endl;
            handle_delay_response(message, sender_addr, relations, sync_level, current_parent, T1, T2, T3);
            break;
        case LEADER:
            cout << "Received LEADER message" << endl;
            handle_leader(message, sync_level);
            break;
        case GET_TIME:
            cout << "Received GET_TIME message" << endl;
            handle_get_time(sender_addr, sync_level, socket, buf);
            break;
        case TIME:
            handle_time();
            cout << "Received TIME message" << endl;
            break;
        case NO_MSG:
            usleep(1000); // No message received, sleep for a while
            break;
        default:
            err_msg("Unknown message type: %d", message.message);
            break;
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    time0 = chrono::high_resolution_clock::now();

    string bind_address = "0.0.0.0"; // Default: listen on all addresses
    int port = 0;                    // Default: any available port
    string peer_address = "";        // Default: no peer address
    int peer_port = 0;               // Default: no peer port

    // Parsing command line arguments
    if (read_from_argv(argc, argv, bind_address, port, peer_address, peer_port) != 0)
    {
        return 1;
    }

    int server_socket = -1;
    sockaddr_in server_addr{};
    if (initialize_socket(server_socket, server_addr, bind_address, port) != 0)
    {
        return 1;
    }

    char *buffer = new char[MAX_DATAGRAM_SIZE];
    // Say Hello

    // Initialize socket for peer connection if peer_address and peer_port are provided
    if (!peer_address.empty() && peer_port > 0)
    {
        if (say_hello(server_socket, peer_address, peer_port, buffer) < 0)
        {
            err_msg("Error sending hello message");
        }
        cout << "Hello message sent to peer at " << peer_address << ":" << peer_port << endl;
    }
    handle_messages(server_socket, buffer, bind_address, port);

    // Wait for hello_reply
    // connect to all the peers
    /*
        while(true){
            czytaj z socketu
            responduj
        }
    */
}